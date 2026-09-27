using System;
using Moq;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Application.Tests.Common;

/// <summary>
/// T�m Application Service testleri i�in merkezi temel s�n�f.
/// 
/// AMA�:
/// - Mock nesnelerini (Repository, PasswordHasher) t�m testlerde tekrar tekrar olu�turmaktan ka��nmak
/// - Test setup'�n� merkezile�tirerek bak�m kolayl��� sa�lamak
/// - DRY (Don't Repeat Yourself) prensibine uymak
/// 
/// G�VENL�K:
/// Her test izole �al��mal�d�r. Bu nedenle her test �ncesi yeni mock'lar olu�turulur.
/// </summary>
public abstract class TestBase : IDisposable
{
        protected Mock<IUserRepository> MockUserRepository { get; private set; }
    protected Mock<IPasswordHasher> MockPasswordHasher { get; private set; }
    protected Mock<ITokenService> MockTokenService { get; private set; }

    protected TestBase()
    {
        MockUserRepository = new Mock<IUserRepository>();
        MockPasswordHasher = new Mock<IPasswordHasher>();
        MockTokenService = new Mock<ITokenService>();
        ResetMocks();
    }

    protected void ResetMocks()
    {
        MockUserRepository.Reset();
        MockPasswordHasher.Reset();
        MockTokenService.Reset();

        MockTokenService
            .Setup(x => x.CreateToken(It.IsAny<VaultGuard.Domain.Entities.User>()))
            .Returns("test.jwt.token");

        MockUserRepository
            .Setup(x => x.ExistsByEmailAsync(It.IsAny<string>(), It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(false);

        MockUserRepository
            .Setup(x => x.ExistsByUsernameAsync(It.IsAny<string>(), It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(false);

        MockPasswordHasher
            .Setup(x => x.HashPassword(It.IsAny<string>()))
            .Returns((string password) => $"hashed_{password}");

        MockPasswordHasher
            .Setup(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(true);

        MockUserRepository
            .Setup(x => x.SaveChangesAsync(It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(1);
    }

    protected void SetupUserExists(User user)
    {
        MockUserRepository
            .Setup(x => x.GetByEmailAsync(user.Email, It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(user);

        MockUserRepository
            .Setup(x => x.GetByUsernameAsync(user.Username, It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(user);

        MockUserRepository
            .Setup(x => x.GetByIdAsync(user.Id, It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(user);

        MockUserRepository
            .Setup(x => x.ExistsByEmailAsync(user.Email, It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(true);

        MockUserRepository
            .Setup(x => x.ExistsByUsernameAsync(user.Username, It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(true);
    }

    protected void SetupUserNotFound()
    {
        MockUserRepository
            .Setup(x => x.GetByEmailAsync(It.IsAny<string>(), It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync((User?)null);

        MockUserRepository
            .Setup(x => x.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync((User?)null);

        MockUserRepository
            .Setup(x => x.GetByIdAsync(It.IsAny<Guid>(), It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync((User?)null);
    }

    protected void SetupPasswordVerifyFails()
    {
        MockPasswordHasher
            .Setup(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(false);
    }

    protected void VerifyNoSaveOccurred()
    {
        MockUserRepository.Verify(
            x => x.SaveChangesAsync(It.IsAny<System.Threading.CancellationToken>()),
            Times.Never);
    }

    protected void VerifySaveOccurredOnce()
    {
        MockUserRepository.Verify(
            x => x.SaveChangesAsync(It.IsAny<System.Threading.CancellationToken>()),
            Times.Once);
    }

    protected void VerifyPasswordHashedOnce()
    {
        MockPasswordHasher.Verify(
            x => x.HashPassword(It.IsAny<string>()),
            Times.Once);
    }

    protected void VerifyPasswordNeverHashed()
    {
        MockPasswordHasher.Verify(
            x => x.HashPassword(It.IsAny<string>()),
            Times.Never);
    }

    public virtual void Dispose()
    {
        MockUserRepository?.Reset();
        MockPasswordHasher?.Reset();
        GC.SuppressFinalize(this);
    }
}