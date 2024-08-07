using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DetecTestApi.Services.AesGcmService
{
    public interface IEncryptionService
    {
        (byte[] EncryptedData, byte[] Nonce, byte[] Tag) Encrypt(string plainText, byte[] key);
        string Decrypt(byte[] cipherText, byte[] key, byte[] nonce, byte[] tag);
    }
}
