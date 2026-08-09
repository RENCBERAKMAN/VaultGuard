using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using VaultGuard.Application.Interfaces;

namespace VaultGuard.Infrastructure.Security
{
    /// <summary>
    /// AES-256-GCM (Authenticated Encryption with Associated Data) algoritmasını kullanan
    /// enterprise-grade şifreleme servisi.
    /// Veritabanında saklanan verilerin maximum güvenlik standardında korunmasını sağlar.
    /// GCM modu hem gizlilik (confidentiality) hem de bütünlük/kimlik doğrulama
    /// (integrity/authenticity) garantisi verir - CBC'nin aksine ciphertext üzerinde
    /// yapılan herhangi bir değişiklik (bit-flipping attack) decrypt aşamasında tespit edilir.
    /// </summary>
    public class AesEncryptionService : IEncryptionService
    {
        // Şifreleme algoritması parametreleri
        private const int AesKeySize = 32;  // 256 bit / 8 = 32 bytes
        private const int NonceSize = 12;   // 96 bit / 8 = 12 bytes (AES-GCM standart nonce boyutu)
        private const int TagSize = 16;     // 128 bit / 8 = 16 bytes (authentication tag boyutu)

        // Configuration'dan okunacak key ismi
        private const string EncryptionKeyConfigKey = "Security:Encryption:Key";

        // Şifreleme anahtarı
        private readonly byte[] _encryptionKey;

        /// <summary>
        /// Constructor: IConfiguration aracılığıyla encryption key'i yükler.
        /// appsettings.json'dan Security:Encryption:Key değerini okur.
        /// 
        /// NOT: GCM modunda IV/nonce config'den sabit olarak okunmaz.
        /// Sabit nonce kullanımı GCM'de kritik bir güvenlik açığıdır (key+nonce reuse
        /// authentication'ı tamamen kırar). Bu yüzden her şifrelemede rastgele
        /// yeni bir nonce üretilir ve ciphertext'in başına eklenir.
        /// </summary>
        /// <param name="configuration">Uygulama konfigürasyonu</param>
        /// <exception cref="ArgumentNullException">Configuration null ise</exception>
        /// <exception cref="InvalidOperationException">Key konfigürasyonu eksik veya geçersiz ise</exception>
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

            // Base64'ten byte dizisine dönüştür
            _encryptionKey = ValidateAndDecodeBase64(keyFromConfig, AesKeySize, "Şifreleme anahtarı");
        }

        /// <summary>
        /// Düz metin string'i AES-256-GCM ile şifreler.
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
        /// Base64 kodlanmış şifrelenmiş string'i AES-256-GCM ile çözer.
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
        /// Düz metin byte dizisini AES-256-GCM ile şifreler.
        /// SİBER GÜVENLİK: Her işlemde rastgele 12 byte'lık benzersiz bir nonce üretir.
        /// Bu, aynı verinin her seferinde farklı görünmesini sağlar (IND-CPA security). 🛡️
        /// Çıktı formatı: Nonce(12 byte) + Ciphertext(N byte) + Tag(16 byte)
        /// </summary>
        /// <param name="plainTextBytes">Şifrelenmek istenen byte dizisi</param>
        /// <returns>Şifrelenmiş byte dizisi (Nonce + Ciphertext + Tag)</returns>
        /// <exception cref="ArgumentNullException">plainTextBytes null ise</exception>
        /// <exception cref="InvalidOperationException">Şifreleme işlemi başarısız ise</exception>
        public byte[] EncryptBytes(byte[] plainTextBytes)
        {
            // Input validation: Veri boş olamaz
            if (plainTextBytes == null || plainTextBytes.Length == 0)
                throw new ArgumentNullException(nameof(plainTextBytes), "Şifrelenmek istenen veri boş olamaz.");

            try
            {
                // --- SİBER GÜVENLİK KRİTİK NOKTASI ---
                // Her şifrelemede rastgele 12 byte'lık benzersiz bir nonce üretir.
                var nonce = new byte[NonceSize];
                RandomNumberGenerator.Fill(nonce);

                var cipherBytes = new byte[plainTextBytes.Length];
                var tag = new byte[TagSize];

                using (var aesGcm = new AesGcm(_encryptionKey, TagSize))
                {
                    // Şifreleme işlemi: plaintext -> ciphertext + authentication tag
                    aesGcm.Encrypt(nonce, plainTextBytes, cipherBytes, tag);
                }

                // PERFORMANS VE STANDART: Nonce + Ciphertext + Tag'i tek bir dizide birleştiriyoruz.
                // Decrypt işlemi sırasında ilk 12 byte nonce, son 16 byte tag olarak okunacaktır.
                var result = new byte[NonceSize + cipherBytes.Length + TagSize];
                Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
                Buffer.BlockCopy(cipherBytes, 0, result, NonceSize, cipherBytes.Length);
                Buffer.BlockCopy(tag, 0, result, NonceSize + cipherBytes.Length, TagSize);

                return result;
            }
            catch (Exception ex)
            {
                // SİBER GÜVENLİK: Hata mesajında algoritma detaylarını veya anahtar bilgisini asla sızdırmaz.
                // Hata sadece iç loglama için 'ex' ile taşınır, dışarıya generic mesaj döner.
                throw new InvalidOperationException("Şifreleme motorunda beklenmeyen bir hata oluştu.", ex);
            }
        }

        /// <summary>
        /// Şifrelenmiş byte dizisini AES-256-GCM ile çözer.
        /// SİBER GÜVENLİK: Verinin başındaki 12 byte'lık nonce ve sonundaki 16 byte'lık
        /// authentication tag ayrıştırılarak çözme işlemi gerçekleştirilir.
        /// Tag doğrulaması başarısız olursa (veri değiştirilmişse) CryptographicException fırlatılır.
        /// </summary>
        /// <param name="cipherTextBytes">Şifrelenmiş byte dizisi (Nonce + Ciphertext + Tag)</param>
        /// <returns>Şifresi çözülmüş byte dizisi</returns>
        /// <exception cref="ArgumentNullException">cipherTextBytes null ise</exception>
        /// <exception cref="InvalidOperationException">Şifre çözme işlemi başarısız ise</exception>
        public byte[] DecryptBytes(byte[] cipherTextBytes)
        {
            // Input validation: Veri boş gelirse işlem yapma
            if (cipherTextBytes == null || cipherTextBytes.Length == 0)
                throw new ArgumentNullException(nameof(cipherTextBytes), "Çözülmek istenen veri boş olamaz.");

            // SİBER GÜVENLİK: Şifreli veri en az Nonce + Tag boyutu kadar olmalıdır.
            // Bu kontrol, bozuk veya eksik verilerin işlemciyi gereksiz yormasını engeller.
            if (cipherTextBytes.Length < NonceSize + TagSize)
                throw new InvalidOperationException("Şifrelenmiş veri formatı geçersiz veya eksik.");

            try
            {
                // --- NONCE / CIPHERTEXT / TAG AYRIŞTIRMA ---
                // Verinin ilk 12 byte'ını (Nonce), son 16 byte'ını (Tag) ve
                // ortada kalanı (Ciphertext) ayırıyoruz.
                // PERFORMANS: Buffer.BlockCopy, byte dizileri için Array.Copy'den daha hızlıdır. 🚀
                var nonce = new byte[NonceSize];
                var tag = new byte[TagSize];
                var cipherLength = cipherTextBytes.Length - NonceSize - TagSize;
                var cipher = new byte[cipherLength];

                Buffer.BlockCopy(cipherTextBytes, 0, nonce, 0, NonceSize);
                Buffer.BlockCopy(cipherTextBytes, NonceSize, cipher, 0, cipherLength);
                Buffer.BlockCopy(cipherTextBytes, NonceSize + cipherLength, tag, 0, TagSize);

                var plainBytes = new byte[cipherLength];

                using (var aesGcm = new AesGcm(_encryptionKey, TagSize))
                {
                    // Çözme işlemi: ciphertext + tag -> plaintext (tag doğrulaması dahili yapılır)
                    aesGcm.Decrypt(nonce, cipher, tag, plainBytes);
                }

                // Bellek temizliğini garanti etmek için sadece sonucu döndür
                return plainBytes;
            }
            catch (CryptographicException)
            {
                // SİBER GÜVENLİK: Yanlış anahtar veya bozulmuş/değiştirilmiş veri durumunda
                // saldırgana teknik hata sızdırmaz. Generic bir güvenlik uyarısı döner.
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