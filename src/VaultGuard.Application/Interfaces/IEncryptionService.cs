namespace VaultGuard.Application.Interfaces
{
    /// <summary>
    /// Þifreleme ve þifre çözme iþlemlerinin soyut arayüzü.
    /// Veri güvenliði için string ve byte[] veri türlerini destekler.
    /// </summary>
    public interface IEncryptionService
    {
        /// <summary>
        /// Düz metin (plaintext) string'i AES-256-CBC ile þifreler.
        /// </summary>
        /// <param name="plainText">Þifrelenmek istenen düz metin</param>
        /// <returns>Base64 kodlanmýþ þifrelenmiþ veri (ciphertext)</returns>
        /// <exception cref="ArgumentNullException">plainText null veya boþ ise</exception>
        /// <exception cref="InvalidOperationException">Þifreleme iþlemi baþarýsýz ise</exception>
        string Encrypt(string plainText);

        /// <summary>
        /// Base64 kodlanmýþ þifrelenmiþ string'i AES-256-CBC ile çözer.
        /// </summary>
        /// <param name="cipherText">Base64 kodlanmýþ þifrelenmiþ veri</param>
        /// <returns>Þifresi çözülmüþ düz metin</returns>
        /// <exception cref="ArgumentNullException">cipherText null veya boþ ise</exception>
        /// <exception cref="InvalidOperationException">Þifre çözme iþlemi baþarýsýz ise</exception>
        string Decrypt(string cipherText);

        /// <summary>
        /// Düz metin byte dizisini AES-256-CBC ile þifreler.
        /// Yüksek hassasiyetli veri (örneðin dosyalar) için optimize edilmiþtir.
        /// </summary>
        /// <param name="plainTextBytes">Þifrelenmek istenen byte dizisi</param>
        /// <returns>Þifrelenmiþ byte dizisi</returns>
        /// <exception cref="ArgumentNullException">plainTextBytes null ise</exception>
        /// <exception cref="InvalidOperationException">Þifreleme iþlemi baþarýsýz ise</exception>
        byte[] EncryptBytes(byte[] plainTextBytes);

        /// <summary>
        /// Þifrelenmiþ byte dizisini AES-256-CBC ile çözer.
        /// Yüksek hassasiyetli veri (örneðin dosyalar) için optimize edilmiþtir.
        /// </summary>
        /// <param name="cipherTextBytes">Þifrelenmiþ byte dizisi</param>
        /// <returns>Þifresi çözülmüþ byte dizisi</returns>
        /// <exception cref="ArgumentNullException">cipherTextBytes null ise</exception>
        /// <exception cref="InvalidOperationException">Þifre çözme iþlemi baþarýsýz ise</exception>
        byte[] DecryptBytes(byte[] cipherTextBytes);
    }
}