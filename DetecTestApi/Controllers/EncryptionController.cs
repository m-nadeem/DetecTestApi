using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System;
using DetecTestApi.Services.AesGcmService;
using DetecTestApi.Models.Encryption;
using DetecTestApi.Models.Decryption;

namespace DetecTestApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {

        private readonly IEncryptionService _aesGcmService;

        public EncryptionController(IEncryptionService aesGcmService)
        {
            _aesGcmService = aesGcmService;
        }

        [HttpPost("encrypt")]
        public IActionResult Encrypt([FromBody] EncryptionRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                var (encryptedData, nonce, tag) = _aesGcmService.Encrypt(request.PlainText, request.Key);
                return Ok(new { EncryptedData = encryptedData, Nonce = nonce, Tag = tag });
            }
            catch (CryptographicException ex)
            {
                return BadRequest(new { Message = "Encryption failed: " + ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An unexpected error occurred: " + ex.Message });
            }
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt([FromBody] DecryptionRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                string decryptedText = _aesGcmService.Decrypt(request.CipherText, request.Key, request.Nonce, request.Tag);
                return Ok(new { DecryptedText = decryptedText });
            }
            catch (CryptographicException ex)
            {
                return BadRequest(new { Message = "Decryption failed: " + ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An unexpected error occurred: " + ex.Message });
            }
        }


    }
}
