using System.ComponentModel.DataAnnotations;

namespace DetecTestApi.Models.Decryption
{
    public class DecryptionRequest
    {
        [Required]
        public required byte[] CipherText { get; set; }

        [Required]
        [MinLength(16), MaxLength(32)]
        public required byte[] Key { get; set; }

        [Required]
        [MinLength(12), MaxLength(12)]
        public required byte[] Nonce { get; set; }

        [Required]
        [MinLength(16), MaxLength(16)]
        public required byte[] Tag { get; set; }
    }
}
