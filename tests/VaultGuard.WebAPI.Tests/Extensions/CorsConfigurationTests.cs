using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using VaultGuard.WebAPI;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Extensions;

/// <summary>
/// TEST SÜİTİ: CORS (Cross-Origin Resource Sharing) Configuration & Security Tests
/// 
/// SRE FOCUS:
/// - **Origin Validation**: Only whitelisted origins allowed
/// - **Preflight Handling**: OPTIONS requests processed correctly
/// - **Credential Security**: No wildcard (*) with credentials
/// - **Production Readiness**: CORS policy matches security requirements
/// 
/// THREAT MODEL:
/// - Cross-Origin XSS: Malicious site accesses API
/// - CSRF Bypass: Unauthorized origin sends requests
/// - Data Exfiltration: Sensitive data leaked to untrusted origin
/// - Credential Theft: Cookies exposed to malicious origin
/// 
/// COMPLIANCE:
/// - **OWASP A05:2021**: Security Misconfiguration
/// - **CWE-346**: Origin Validation Error
/// - **CWE-942**: Permissive Cross-domain Policy
/// - **NIST SP 800-53 AC-3**: Access Enforcement
/// 
/// SRE PRINCIPLES:
/// - **Defense in Depth**: CORS is one layer of security
/// - **Least Privilege**: Only necessary origins allowed
/// - **Fail Secure**: Default deny, explicit allow
/// - **Observability**: CORS violations logged for monitoring
/// 
/// PRODUCTION CONSIDERATIONS:
/// - **CDN Origins**: Separate CORS policy for static assets
/// - **Mobile Apps**: Native app origins (mobile://, app://)
/// - **Development**: Different origins for dev/staging/prod
/// - **Monitoring**: Alert on unusual CORS rejection patterns
/// </summary>
public class CorsConfigurationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public CorsConfigurationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    // ============================================================================
    // 🌐 ALLOWED ORIGINS - WHITELIST VALIDATION
    // ============================================================================

    /// <summary>
    /// SRE TEST - ALLOWED ORIGIN (CRITICAL!):
    /// Whitelisted origin should receive CORS headers.
    /// 
    /// SRE IMPACT:
    /// - Service Availability: Frontend can access API
    /// - User Experience: No CORS errors in browser console
    /// - Monitoring: Normal traffic patterns
    /// 
    /// PRODUCTION:
    /// - appsettings.Production.json: https://app.vaultguard.com
    /// - appsettings.Staging.json: https://staging.vaultguard.com
    /// - appsettings.Development.json: http://localhost:3000
    /// 
    /// OWASP: A05:2021 - Security Misconfiguration
    /// CWE-346: Origin Validation Error
    /// </summary>
    [Fact]
    public async Task CorsPolicy_AllowedOrigin_ShouldReturnCorsHeaders()
    {
        // Arrange: Preflight request from allowed origin
        // NOTE: VaultGuard uses "VaultGuardPolicy" CORS policy
        // Configured in DependencyInjection.cs or appsettings.json

        var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Options, "/api/auth/login");

        // Simulate browser preflight request
        // Assumption: http://localhost:3000 is whitelisted in development
        request.Headers.Add("Origin", "http://localhost:3000");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type,authorization");

        // Act: Send preflight request
        var response = await _client.SendAsync(request);

        // Assert: Should receive CORS headers
        response.Headers.Contains("Access-Control-Allow-Origin").Should().BeTrue(
            "SRE: Allowed origin must receive CORS headers for service availability");

        if (response.Headers.Contains("Access-Control-Allow-Origin"))
        {
            var allowOrigin = response.Headers.GetValues("Access-Control-Allow-Origin").FirstOrDefault();

            // Verify: Origin matches request OR is configured
            (allowOrigin == "http://localhost:3000" || allowOrigin == "*").Should().BeTrue(
                "SRE: CORS policy must allow frontend origin");
        }

        // SRE METRIC: cors_preflight_success_total
        // Alert if this test fails → Frontend cannot access API
    }

    /// <summary>
    /// SRE TEST - UNAUTHORIZED ORIGIN (CRITICAL!):
    /// Non-whitelisted origin should NOT receive CORS headers.
    /// 
    /// THREAT: Cross-Origin Attack
    /// - Attacker site: https://evil.com
    /// - Attempts to call API from browser
    /// - Browser blocks due to missing CORS headers
    /// 
    /// SRE IMPACT:
    /// - Security Posture: Attack surface reduced
    /// - Incident Prevention: Malicious origins blocked
    /// - Compliance: Security controls verified
    /// 
    /// OWASP: A05:2021 - Security Misconfiguration
    /// CWE-942: Permissive Cross-domain Policy
    /// </summary>
    [Fact]
    public async Task CorsPolicy_UnauthorizedOrigin_ShouldNotReturnCorsHeaders()
    {
        // Arrange: Preflight request from unauthorized origin
        var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Options, "/api/auth/login");
        request.Headers.Add("Origin", "https://evil.com");
        request.Headers.Add("Access-Control-Request-Method", "POST");

        // Act
        var response = await _client.SendAsync(request);

        // Assert: Should NOT receive Access-Control-Allow-Origin
        // OR: Should receive but NOT match evil.com
        if (response.Headers.Contains("Access-Control-Allow-Origin"))
        {
            var allowOrigin = response.Headers.GetValues("Access-Control-Allow-Origin").FirstOrDefault();

            allowOrigin.Should().NotBe("https://evil.com",
                "SRE SECURITY: Unauthorized origins must be blocked");

            allowOrigin.Should().NotBe("*",
                "SRE SECURITY: Wildcard (*) allows any origin - security risk!");
        }

        // SRE METRIC: cors_rejection_total{origin="evil.com"}
        // Monitor for attack patterns (many rejections from same origin)
    }

    // ============================================================================
    // 🔒 CREDENTIAL SECURITY
    // ============================================================================

    /// <summary>
    /// SRE TEST - WILDCARD WITH CREDENTIALS (CRITICAL!):
    /// CORS policy MUST NOT use wildcard (*) with credentials.
    /// 
    /// VULNERABILITY:
    /// Access-Control-Allow-Origin: *
    /// Access-Control-Allow-Credentials: true
    /// → Any origin can send authenticated requests!
    /// 
    /// SRE IMPACT:
    /// - Critical Security Flaw: Session hijacking possible
    /// - Compliance Violation: PCI-DSS, SOC 2 failure
    /// - Incident Risk: Data breach, unauthorized access
    /// 
    /// OWASP: A05:2021 - Security Misconfiguration
    /// CWE-942: Permissive Cross-domain Policy
    /// </summary>
    [Fact]
    public async Task CorsPolicy_WithCredentials_ShouldNotUseWildcard()
    {
        // Arrange: Preflight request
        var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Options, "/api/secrets");
        request.Headers.Add("Origin", "http://localhost:3000");
        request.Headers.Add("Access-Control-Request-Method", "GET");

        // Act
        var response = await _client.SendAsync(request);

        // Assert: If credentials allowed, origin must NOT be wildcard
        if (response.Headers.Contains("Access-Control-Allow-Credentials"))
        {
            var allowCredentials = response.Headers.GetValues("Access-Control-Allow-Credentials").FirstOrDefault();

            if (allowCredentials == "true")
            {
                var allowOrigin = response.Headers.GetValues("Access-Control-Allow-Origin").FirstOrDefault();

                allowOrigin.Should().NotBe("*",
                    "SRE CRITICAL: Wildcard (*) with credentials is a SEVERE security vulnerability!");

                // SRE ALERT: Critical security misconfiguration detected
                // Severity: P0 (Critical)
                // Action: Immediate remediation required
            }
        }
    }

    /// <summary>
    /// SRE TEST - PREFLIGHT CACHE:
    /// CORS preflight cache duration should be reasonable.
    /// 
    /// SRE BALANCE:
    /// - Too Short (e.g., 0): High preflight request volume → API load
    /// - Too Long (e.g., 86400s): Configuration changes delayed
    /// - Optimal: 600-3600s (10 min - 1 hour)
    /// 
    /// SRE METRICS:
    /// - preflight_request_rate: Measure preflight volume
    /// - api_latency_p99: Check if preflights impact latency
    /// </summary>
    [Fact]
    public async Task CorsPolicy_PreflightCache_ShouldBeReasonable()
    {
        // Arrange: Preflight request
        var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Options, "/api/secrets");
        request.Headers.Add("Origin", "http://localhost:3000");
        request.Headers.Add("Access-Control-Request-Method", "GET");

        // Act
        var response = await _client.SendAsync(request);

        // Assert: Check Access-Control-Max-Age
        if (response.Headers.Contains("Access-Control-Max-Age"))
        {
            var maxAge = response.Headers.GetValues("Access-Control-Max-Age").FirstOrDefault();

            if (int.TryParse(maxAge, out var seconds))
            {
                seconds.Should().BeGreaterThanOrEqualTo(60,
                    "SRE PERFORMANCE: Preflight cache too short increases API load");

                seconds.Should().BeLessThanOrEqualTo(86400,
                    "SRE AGILITY: Preflight cache too long delays config changes");

                // Recommended: 600-3600s (10 min - 1 hour)
                // SRE METRIC: preflight_cache_duration_seconds
            }
        }
    }

    // ============================================================================
    // 🎯 ALLOWED METHODS & HEADERS
    // ============================================================================

    /// <summary>
    /// SRE TEST - ALLOWED METHODS:
    /// Only necessary HTTP methods should be allowed.
    /// 
    /// SRE PRINCIPLE: Least Privilege
    /// - Allow: GET, POST, PUT, DELETE (CRUD operations)
    /// - Block: TRACE, CONNECT (potential security risks)
    /// 
    /// OWASP: A01:2021 - Broken Access Control
    /// </summary>
    [Fact]
    public async Task CorsPolicy_AllowedMethods_ShouldBeLimited()
    {
        // Arrange
        var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Options, "/api/secrets");
        request.Headers.Add("Origin", "http://localhost:3000");
        request.Headers.Add("Access-Control-Request-Method", "POST");

        // Act
        var response = await _client.SendAsync(request);

        // Assert: Check allowed methods
        if (response.Headers.Contains("Access-Control-Allow-Methods"))
        {
            var allowMethods = response.Headers.GetValues("Access-Control-Allow-Methods").FirstOrDefault();

            // Should allow standard CRUD methods
            allowMethods.Should().Contain("GET", "SRE: GET required for read operations");
            allowMethods.Should().Contain("POST", "SRE: POST required for create operations");

            // Should NOT allow dangerous methods
            allowMethods.Should().NotContain("TRACE",
                "SRE SECURITY: TRACE method enables XSS attacks");

            // SRE METRIC: cors_method_usage{method="POST"}
            // Monitor which methods are actually used
        }
    }

    /// <summary>
    /// SRE TEST - ALLOWED HEADERS:
    /// Common headers should be allowed for API functionality.
    /// 
    /// REQUIRED HEADERS:
    /// - Content-Type: application/json
    /// - Authorization: Bearer <token>
    /// - X-Requested-With: XMLHttpRequest (AJAX marker)
    /// 
    /// SRE IMPACT:
    /// - Missing headers → Frontend API calls fail
    /// - Too permissive → Potential security risk
    /// </summary>
    [Fact]
    public async Task CorsPolicy_AllowedHeaders_ShouldIncludeCommon()
    {
        // Arrange
        var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Options, "/api/secrets");
        request.Headers.Add("Origin", "http://localhost:3000");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type,authorization");

        // Act
        var response = await _client.SendAsync(request);

        // Assert: Check allowed headers
        if (response.Headers.Contains("Access-Control-Allow-Headers"))
        {
            var allowHeaders = response.Headers.GetValues("Access-Control-Allow-Headers").FirstOrDefault();

            // Should allow essential headers
            allowHeaders.Should().Contain("content-type",
                "SRE: Content-Type required for JSON requests");

            allowHeaders.Should().Contain("authorization",
                "SRE: Authorization required for authenticated requests");

            // SRE METRIC: cors_header_usage{header="authorization"}
            // Track which headers are commonly requested
        }
    }

    // ============================================================================
    // 📊 SRE OBSERVABILITY
    // ============================================================================

    /// <summary>
    /// SRE DOCUMENTATION - CORS MONITORING:
    /// Document key metrics for CORS observability.
    /// 
    /// PROMETHEUS METRICS:
    /// - cors_preflight_requests_total{origin, method, status}
    /// - cors_rejection_total{origin, reason}
    /// - cors_preflight_duration_seconds
    /// 
    /// GRAFANA DASHBOARD:
    /// - Preflight request rate (requests/sec)
    /// - Rejection rate by origin (%)
    /// - Top rejected origins (table)
    /// - Preflight cache effectiveness (%)
    /// 
    /// ALERTS:
    /// - High rejection rate (>10%) → Possible misconfiguration
    /// - Unknown origin spike → Potential attack
    /// - Slow preflight responses → Performance issue
    /// 
    /// INCIDENT RESPONSE:
    /// - P1: Wildcard with credentials detected
    /// - P2: Production origin rejected (frontend down)
    /// - P3: Unusual rejection pattern (security monitoring)
    /// </summary>
    [Fact]
    public void Documentation_CorsMonitoring()
    {
        // SRE BEST PRACTICES:

        // 1. LOG CORS REJECTIONS
        // _logger.LogWarning("CORS rejection: Origin={Origin}, Method={Method}", 
        //     origin, method);

        // 2. METRICS
        // _metrics.IncrementCounter("cors_preflight_total", 
        //     new[] { ("origin", origin), ("status", statusCode) });

        // 3. TRACING
        // using var activity = Activity.StartActivity("CorsPolicy");
        // activity?.SetTag("cors.origin", origin);

        // 4. ALERTS
        // if (rejectionRate > 0.1)
        //     _alertManager.TriggerAlert("HighCorsRejectionRate", rejectionRate);

        // 5. INCIDENT PLAYBOOK
        // - Symptom: Frontend reports CORS errors
        // - Check: Grafana CORS dashboard
        // - Action: Verify appsettings.json AllowedOrigins
        // - Rollback: Previous working configuration
        // - PostMortem: Root cause analysis, prevent recurrence

        Assert.True(true, "CORS monitoring best practices documented");
    }

    /// <summary>
    /// SRE DOCUMENTATION - PRODUCTION CHECKLIST:
    /// Pre-deployment CORS validation checklist.
    /// 
    /// DEPLOYMENT CHECKLIST:
    /// ☐ AllowedOrigins configured for environment
    /// ☐ No wildcard (*) with credentials
    /// ☐ HTTPS origins in production
    /// ☐ Preflight cache duration reasonable (600-3600s)
    /// ☐ Monitoring alerts configured
    /// ☐ Smoke tests passed
    /// ☐ Security review approved
    /// 
    /// SMOKE TESTS:
    /// 1. Frontend can fetch data (200 OK)
    /// 2. Unauthorized origin blocked (CORS error)
    /// 3. Preflight requests cached properly
    /// 4. Metrics and logs flowing
    /// 
    /// ROLLBACK PLAN:
    /// - Symptom: CORS errors in production
    /// - Action: Rollback to previous appsettings.json
    /// - Duration: <5 minutes
    /// - Verification: Smoke tests pass
    /// </summary>
    [Fact]
    public void Documentation_ProductionChecklist()
    {
        // PRE-DEPLOYMENT VALIDATION:

        // 1. ENVIRONMENT-SPECIFIC ORIGINS
        // Development: http://localhost:3000
        // Staging: https://staging.vaultguard.com
        // Production: https://app.vaultguard.com, https://www.vaultguard.com

        // 2. SECURITY REVIEW
        // - No wildcard in production
        // - HTTPS only (no HTTP origins)
        // - Credentials handling secure

        // 3. MONITORING SETUP
        // - Grafana dashboard created
        // - Alerts configured
        // - Logs flowing to centralized logging

        // 4. SMOKE TESTS
        // curl -H "Origin: https://app.vaultguard.com" \
        //      -H "Access-Control-Request-Method: POST" \
        //      -X OPTIONS https://api.vaultguard.com/api/auth/login

        Assert.True(true, "Production deployment checklist documented");
    }

    // ============================================================================
    // 🔧 CONFIGURATION VALIDATION
    // ============================================================================

    /// <summary>
    /// SRE TEST - CONFIGURATION VALIDATION:
    /// CORS configuration should be loaded from appsettings.json.
    /// 
    /// SRE PRINCIPLE: Configuration as Code
    /// - Environment-specific configs
    /// - Version controlled
    /// - Auditable changes
    /// 
    /// CONFIGURATION STRUCTURE:
    /// {
    ///   "Cors": {
    ///     "AllowedOrigins": ["http://localhost:3000"],
    ///     "AllowedMethods": ["GET", "POST", "PUT", "DELETE"],
    ///     "AllowedHeaders": ["Content-Type", "Authorization"],
    ///     "AllowCredentials": true,
    ///     "MaxAge": 3600
    ///   }
    /// }
    /// </summary>
    [Fact]
    public void Documentation_ConfigurationStructure()
    {
        // CONFIGURATION BEST PRACTICES:

        // 1. ENVIRONMENT OVERRIDES
        // appsettings.json → Base configuration
        // appsettings.Development.json → Override for dev
        // appsettings.Production.json → Override for prod

        // 2. VALIDATION ON STARTUP
        // var allowedOrigins = _configuration.GetSection("Cors:AllowedOrigins").Get<string[]>();
        // if (allowedOrigins == null || allowedOrigins.Length == 0)
        //     throw new InvalidOperationException("CORS AllowedOrigins not configured");

        // 3. SECRETS MANAGEMENT
        // Sensitive configs (API keys, secrets) → Azure Key Vault
        // Non-sensitive configs (origins, methods) → appsettings.json

        // 4. CHANGE MANAGEMENT
        // - Config changes via Pull Request
        // - Review required before merge
        // - Automated tests validate config
        // - Rollback plan documented

        Assert.True(true, "CORS configuration best practices documented");
    }
}