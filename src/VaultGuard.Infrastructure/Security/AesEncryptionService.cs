using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using Microsoft.Extensions.Configuration;
using VaultGuard.Application.Interfaces;

namespace VaultGuard.Infrastructure.Security
{
    /// <summary>
    /// AES-256-CBC PKCS7 algoritmasını kullanan enterprise-grade şifreleme servisi.
    /// Veritabanında saklanan verilerin maximum güvenlik standardında korunmasını sağlar.
    /// </summary>
    public class AesEncryptionService : IEncryptionService
    {
        // Şifreleme algoritması parametreleri
        private const int AesKeySize = 32; // 256 bit / 8 = 32 bytes
        private const int AesIvSize = 16;  // 128 bit / 8 = 16 bytes (CBC modu için standart)
        private const int AesBlockSize = 128; // Bit cinsinden

        // Configuration'dan okunacak key isimleri
        private const string EncryptionKeyConfigKey = "Security:Encryption:Key";
        private const string EncryptionIvConfigKey = "Security:Encryption:IV";

        // Şifreleme anahtarı ve ilk vektörü
        private readonly byte[] _encryptionKey;
        private readonly byte[] _encryptionIv;

        /// <summary>
        /// Constructor: IConfiguration aracılığıyla encryption key ve IV'yi yükler.
        /// appsettings.json'dan Security:Encryption:Key ve Security:Encryption:IV değerlerini okur.
        /// </summary>
        /// <param name="configuration">Uygulama konfigürasyonu</param>
        /// <exception cref="ArgumentNullException">Configuration null ise</exception>
        /// <exception cref="InvalidOperationException">Key veya IV konfigürasyonu eksik veya geçersiz ise</exception>
        public AesEncryptionService(IConfiguration configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration), "Configuration nesnesi null olamaz.");

            // Konfigürasyondan encryption key'i oku
            var keyFromConfig = configuration[EncryptionKeyConfigKey];
            if (string.IsNullOrWhiteSpace(keyFromConfig))
                throw new InvalidOperationException(
                    $"Şifreleme anahtarı konfigürasyonda bulunamadı. " +
                    $"'{EncryptionKeyConfigKey}' key'i appsettings.json dosyasında tanımlanmalıdır.");

            // Konfigürasyondan IV'yi oku
            var ivFromConfig = configuration[EncryptionIvConfigKey];
            if (string.IsNullOrWhiteSpace(ivFromConfig))
                throw new InvalidOperationException(
                    $"İlk vektör (IV) konfigürasyonda bulunamadı. " +
                    $"'{EncryptionIvConfigKey}' key'i appsettings.json dosyasında tanımlanmalıdır.");

            // Base64'ten byte dizisine dönüştür
            _encryptionKey = ValidateAndDecodeBase64(keyFromConfig, AesKeySize, "Şifreleme anahtarı");
            _encryptionIv = ValidateAndDecodeBase64(ivFromConfig, AesIvSize, "İlk vektör (IV)");
        }

        /// <summary>
        /// Düz metin string'i AES-256-CBC PKCS7 ile şifreler.
        /// Sonuç Base64 formatında kodlanmış olarak döndürülür.
        /// </summary>
        /// <param name="plainText">Şifrelenmek istenen düz metin</param>
        /// <returns>Base64 kodlanmış şifrelenmiş veri</returns>
        /// <exception cref="ArgumentNullException">plainText null veya boş ise</exception>
        /// <exception cref="InvalidOperationException">Şifreleme işlemi başarısız ise</exception>
        public string Encrypt(string plainText)
        {
            // Input validation (güvenli hata mesajı)
            if (string.IsNullOrWhiteSpace(plainText))
                throw new ArgumentNullException(nameof(plainText), "Şifrelmek istediğiniz veri boş olamaz.");

            try
            {
                // String'i UTF-8 byte dizisine dönüştür
                var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

                // Byte dizisini şifrele
                var encryptedBytes = EncryptBytes(plainTextBytes);

                // Şifrelenmiş byte dizisini Base64'e kodla
                return Convert.ToBase64String(encryptedBytes);
            }
            catch (ArgumentNullException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Sistem detayı sızdırmayan güvenli error mesajı
                throw new InvalidOperationException(
                    "Veri şifreleme işlemi sırasında bir hata oluştu. " +
                    "Lütfen giriş verilerinizi kontrol edip tekrar deneyin.", ex);
            }
        }

        /// <summary>
        /// Base64 kodlanmış şifrelenmiş string'i AES-256-CBC PKCS7 ile çözer.
        /// Şifresi çözülmüş veriler string formatında döndürülür.
        /// </summary>
        /// <param name="cipherText">Base64 kodlanmış şifrelenmiş veri</param>
        /// <returns>Şifresi çözülmüş düz metin</returns>
        /// <exception cref="ArgumentNullException">cipherText null veya boş ise</exception>
        /// <exception cref="InvalidOperationException">Şifre çözme işlemi başarısız ise</exception>
        public string Decrypt(string cipherText)
        {
            // Input validation (güvenli hata mesajı)
            if (string.IsNullOrWhiteSpace(cipherText))
                throw new ArgumentNullException(nameof(cipherText), "Çözmek istediğiniz şifrelenmiş veri boş olamaz.");

            try
            {
                // Base64'ten byte dizisine dönüştür
                var cipherTextBytes = Convert.FromBase64String(cipherText);

                // Byte dizisini çöz
                var decryptedBytes = DecryptBytes(cipherTextBytes);

                // Byte dizisini UTF-8 string'e dönüştür
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (FormatException)
            {
                // Base64 decode hatası için güvenli hata mesajı
                throw new InvalidOperationException(
                    "Şifrelenmiş veri geçersiz formatta. Verinin bozuk olduğu veya değiştirildiği mümkündür.", null);
            }
            catch (ArgumentNullException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Sistem detayı sızdırmayan güvenli error mesajı
                throw new InvalidOperationException(
                    "Veri şifre çözme işlemi sırasında bir hata oluştu. " +
                    "Doğru anahtarla çözüp çözemediğinizi kontrol edin.", ex);
            }
        }

        /// <summary>
        /// Düz metin byte dizisini AES-256-CBC PKCS7 ile şifreler.
        /// Bellek optimizasyonu için using blokları kullanılmıştır.
        /// </summary>
        /// <param name="plainTextBytes">Şifrelenmek istenen byte dizisi</param>
        /// <returns>Şifrelenmiş byte dizisi (IV + ciphertext)</returns>
        /// <exception cref="ArgumentNullException">plainTextBytes null ise</exception>
        /// <exception cref="InvalidOperationException">Şifreleme işlemi başarısız ise</exception>
        /// <summary>
        /// Düz metin byte dizisini AES-256-CBC PKCS7 ile şifreler.
        /// SİBER GÜVENLİK: Her işlemde rastgele IV (Initialization Vector) üreterek deterministik şifrelemeyi engeller.
        /// </summary>
        public byte[] EncryptBytes(byte[] plainTextBytes)
        {
            // Input validation: Veri boş olamaz
            if (plainTextBytes == null || plainTextBytes.Length == 0)
                throw new ArgumentNullException(nameof(plainTextBytes), "Şifrelenmek istenen veri boş olamaz.");

            try
            {
                // AES nesnesini güvenli ve optimize edilmiş şekilde oluştur
                using (var aes = Aes.Create())
                {
                    aes.Key = _encryptionKey;

                    // --- SİBER GÜVENLİK KRİTİK NOKTASI ---
                    // Her şifrelemede rastgele 16 byte'lık benzersiz bir IV üretir.
                    // Bu, aynı şifrenin her seferinde farklı görünmesini sağlar. 🛡️
                    aes.GenerateIV();
                    var currentIv = aes.IV;

                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.BlockSize = AesBlockSize;
                    aes.KeySize = AesKeySize * 8; // 256-bit

                    using (var encryptor = aes.CreateEncryptor(aes.Key, currentIv))
                    using (var memoryStream = new MemoryStream())
                    {
                        // PERFORMANS VE STANDART: IV'yi şifreli metnin en başına ekliyoruz (Prepend).
                        // Decrypt işlemi sırasında ilk 16 byte IV olarak okunacaktır.
                        memoryStream.Write(currentIv, 0, currentIv.Length);

                        using (var cryptoStream = new CryptoStream(
                            memoryStream,
                            encryptor,
                            CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

                            // Padding'i tamamla ve veriyi stream'e mühürle
                            cryptoStream.FlushFinalBlock();

                            // Bellek yönetimini optimize etmek için sadece gerekli byte dizisini döndür
                            return memoryStream.ToArray();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // SİBER GÜVENLİK: Hata mesajında algoritma detaylarını veya anahtar bilgisini asla sızdırmaz.
                // Hata sadece iç loglama için 'ex' ile taşınır, dışarıya generic mesaj döner.
                throw new InvalidOperationException("Şifreleme motorunda beklenmeyen bir hata oluştu.", ex);
            }
        }

        /// <summary>
        /// Şifrelenmiş byte dizisini AES-256-CBC PKCS7 ile çözer.
        /// Bellek optimizasyonu için using blokları kullanılmıştır.
        /// </summary>
        /// <param name="cipherTextBytes">Şifrelenmiş byte dizisi (IV + ciphertext)</param>
        /// <returns>Şifresi çözülmüş byte dizisi</returns>
        /// <exception cref="ArgumentNullException">cipherTextBytes null ise</exception>
        /// <exception cref="InvalidOperationException">Şifre çözme işlemi başarısız ise</exception>
        /// <summary>
        /// Şifrelenmiş byte dizisini AES-256-CBC PKCS7 ile çözer.
        /// SİBER GÜVENLİK: Verinin başındaki 16 byte'lık rastgele IV'yi ayrıştırarak çözme işlemini gerçekleştirir.
        /// </summary>
        public byte[] DecryptBytes(byte[] cipherTextBytes)
        {
            // Input validation: Veri boş gelirse işlem yapma
            if (cipherTextBytes == null || cipherTextBytes.Length == 0)
                throw new ArgumentNullException(nameof(cipherTextBytes), "Çözülmek istenen veri boş olamaz.");

            // SİBER GÜVENLİK: Şifreli veri en az bir IV bloğu (16 byte) kadar olmalıdır.
            // Bu kontrol, bozuk veya eksik verilerin işlemciyi gereksiz yormasını engeller.
            if (cipherTextBytes.Length < AesIvSize)
                throw new InvalidOperationException("Şifrelenmiş veri formatı geçersiz veya eksik.");

            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = _encryptionKey;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.BlockSize = AesBlockSize;
                    aes.KeySize = AesKeySize * 8; // 256-bit

                    // --- IV AYRIŞTIRMA ---
                    // Verinin ilk 16 byte'ını (IV) ve geri kalanını (Ciphertext) ayırıyoruz.
                    // PERFORMANS: Buffer.BlockCopy, byte dizileri için Array.Copy'den daha hızlıdır. 🚀
                    byte[] iv = new byte[AesIvSize];
                    byte[] cipher = new byte[cipherTextBytes.Length - AesIvSize];

                    Buffer.BlockCopy(cipherTextBytes, 0, iv, 0, AesIvSize);
                    Buffer.BlockCopy(cipherTextBytes, AesIvSize, cipher, 0, cipher.Length);

                    // Çözücü motoru (Decryptor), ayrıştırılan IV ile başlatılır
                    using (var decryptor = aes.CreateDecryptor(aes.Key, iv))
                    using (var memoryStream = new MemoryStream(cipher))
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (var resultStream = new MemoryStream())
                    {
                        // Çözülen veriyi akış üzerinden sonuç stream'ine kopyala
                        cryptoStream.CopyTo(resultStream);

                        // Bellek temizliğini garanti etmek için sadece sonucu döndür
                        return resultStream.ToArray();
                    }
                }
            }
            catch (CryptographicException)
            {
                // SİBER GÜVENLİK: Yanlış anahtar veya bozulmuş padding durumunda saldırgana
                // teknik hata (Padding Error vb.) sızdırmaz. Generic bir güvenlik uyarısı döner.
                throw new InvalidOperationException("Güvenlik anahtarı uyuşmazlığı veya veri bütünlüğü hatası saptandı.", null);
            }
            catch (Exception ex)
            {
                // Beklenmedik sistem hataları için generic mesaj
                throw new InvalidOperationException("Şifre çözme motorunda kritik bir hata oluştu.", ex);
            }
        }

        /// <summary>
        /// Base64 string'i byte dizisine dönüştürür ve boyut kontrolü yapar.
        /// Güvenli konfigürasyon doğrulaması için kullanılır.
        /// </summary>
        /// <param name="base64String">Base64 formatında kodlanmış string</param>
        /// <param name="expectedSize">Beklenen byte dizisi boyutu</param>
        /// <param name="parameterName">Parametre adı (hata mesajında kullanılır)</param>
        /// <returns>Dekode edilmiş byte dizisi</returns>
        /// <exception cref="InvalidOperationException">Format veya boyut hatalı ise</exception>
        private static byte[] ValidateAndDecodeBase64(string base64String, int expectedSize, string parameterName)
        {
            try
            {
                var decodedBytes = Convert.FromBase64String(base64String);

                // Boyut kontrolü
                if (decodedBytes.Length != expectedSize)
                    throw new InvalidOperationException(
                        $"{parameterName} geçersiz boyutta. " +
                        $"Beklenen: {expectedSize} byte, Alınan: {decodedBytes.Length} byte. " +
                        $"appsettings.json dosyasındaki değeri kontrol edin.");

                return decodedBytes;
            }
            catch (FormatException)
            {
                throw new InvalidOperationException(
                    $"{parameterName} geçersiz Base64 formatında. " +
                    $"appsettings.json dosyasında Base64 kodlanmış değer sağlayın.");
            }
        }
    }
}