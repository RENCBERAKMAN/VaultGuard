using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace VaultGuard.WebAPI.Filters;

public class ValidationFilter : IAsyncActionFilter
{
    private readonly ILogger<ValidationFilter> _logger;

    public ValidationFilter(ILogger<ValidationFilter> logger)
    {
        _logger = logger;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument == null) continue;

            var argumentType = argument.GetType();

            // System tiplerini veya token'ları validasyon dışı tut
            if (argumentType.Namespace != null && 
                (argumentType.Namespace.StartsWith("System") || argumentType.Name.Contains("CancellationToken")))
            {
                continue;
            }

            var validatorType = typeof(IValidator<>).MakeGenericType(argumentType);
            var validator = context.HttpContext.RequestServices.GetService(validatorType) as IValidator;

            if (validator == null)
            {
                // DEBUG: Validator bulunamadı
                _logger.LogWarning("VALIDATOR NOT FOUND for type: {Type}", argumentType.FullName);
                continue;
            }

            var validationContext = new ValidationContext<object>(argument);
            var validationResult = await validator.ValidateAsync(validationContext);

            if (!validationResult.IsValid)
            {
                var errors = validationResult.Errors
                    .GroupBy(e => e.PropertyName)
                    .ToDictionary(
                        g => g.Key,
                        g => g.Select(e => e.ErrorMessage).ToArray());

                context.Result = new BadRequestObjectResult(new
                {
                    success = false,
                    message = "Validation failed. Please check your input.",
                    errors
                });
                return;
            }
        }

        await next();
    }
}