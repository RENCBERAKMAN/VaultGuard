namespace VaultGuard.Application.Interfaces;

public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
    byte[] EncryptBytes(byte[] plainTextBytes);
    byte[] DecryptBytes(byte[] cipherTextBytes);
}