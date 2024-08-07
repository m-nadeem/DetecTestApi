using System.Security.Cryptography;
using System.Text;

namespace DetecTestApi.Services.AesGcmService
{
    public class EncryptionService : IEncryptionService
    {
        public (byte[] EncryptedData, byte[] Nonce, byte[] Tag) Encrypt(string plainText, byte[] key)
        {
            if (string.IsNullOrWhiteSpace(plainText)) throw new ArgumentNullException(nameof(plainText));
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
                throw new ArgumentException("Invalid key length", nameof(key));

            using (AesGcm aesGcm = new AesGcm(key))
            {
                byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // Usually 12 bytes
                byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize]; // Usually 16 bytes
                byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherText = new byte[plainTextBytes.Length];

                // Generate a random nonce
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(nonce);
                }

                // Perform encryption
                aesGcm.Encrypt(nonce, plainTextBytes, cipherText, tag);

                return (cipherText, nonce, tag);
            }
        }

        public string Decrypt(byte[] cipherText, byte[] key, byte[] nonce, byte[] tag)
        {
            if (cipherText == null || cipherText.Length == 0) throw new ArgumentNullException(nameof(cipherText));
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
                throw new ArgumentException("Invalid key length", nameof(key));
            if (nonce == null || nonce.Length != AesGcm.NonceByteSizes.MaxSize)
                throw new ArgumentException("Invalid nonce length", nameof(nonce));
            if (tag == null || tag.Length != AesGcm.TagByteSizes.MaxSize)
                throw new ArgumentException("Invalid tag length", nameof(tag));

            using (AesGcm aesGcm = new AesGcm(key))
            {
                byte[] decryptedBytes = new byte[cipherText.Length];

                // Perform decryption
                aesGcm.Decrypt(nonce, cipherText, tag, decryptedBytes);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }


    }
}
