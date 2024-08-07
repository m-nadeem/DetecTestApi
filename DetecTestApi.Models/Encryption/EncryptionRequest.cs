using System.ComponentModel.DataAnnotations;

namespace DetecTestApi.Models.Encryption
{
    public class EncryptionRequest
    {
        [Required]
        public string PlainText { get; set; }

        [Required]
        [MinLength(16), MaxLength(32)]
        public byte[] Key { get; set; }
    }
}
