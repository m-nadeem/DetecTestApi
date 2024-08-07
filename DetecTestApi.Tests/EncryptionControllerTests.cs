using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Cryptography;
using DetecTestApi.Services.AesGcmService;
using DetecTestApi.Controllers;
using DetecTestApi.Models.Encryption;
using DetecTestApi.Models.Decryption;

namespace DetecTestApi.Tests
{
    public class EncryptionControllerTests
    {
        private readonly Mock<IEncryptionService> _mockAesGcmService;
        private readonly EncryptionController _controller;

        public EncryptionControllerTests()
        {
            _mockAesGcmService = new Mock<IEncryptionService>();
            _controller = new EncryptionController(_mockAesGcmService.Object);
        }

        [Fact]
        public void Encrypt_ValidRequest_ReturnsOkResult()
        {
            // Arrange
            var request = new EncryptionRequest
            {
                PlainText = "Hello, AES-GCM!",
                Key = new byte[32] // 256-bit key
            };
            var encryptedData = new byte[] { 1, 2, 3 };
            var nonce = new byte[] { 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var tag = new byte[] { 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28 };

            _mockAesGcmService
                .Setup(s => s.Encrypt(It.IsAny<string>(), It.IsAny<byte[]>()))
                .Returns((encryptedData, nonce, tag));

            // Act
            var result = _controller.Encrypt(request);

            // Assert
            var okResult = result as OkObjectResult;
            okResult.Should().NotBeNull();
            okResult.StatusCode.Should().Be(200);
            var response = okResult.Value as dynamic;
            ((byte[])response.EncryptedData).Should().BeEquivalentTo(encryptedData);
            ((byte[])response.Nonce).Should().BeEquivalentTo(nonce);
            ((byte[])response.Tag).Should().BeEquivalentTo(tag);
        }

        [Fact]
        public void Encrypt_InvalidRequest_ReturnsBadRequest()
        {
            // Arrange
            _controller.ModelState.AddModelError("PlainText", "Required");

            var request = new EncryptionRequest
            {
                PlainText = null,
                Key = new byte[32] // 256-bit key
            };

            // Act
            var result = _controller.Encrypt(request);

            // Assert
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Should().NotBeNull();
            badRequestResult.StatusCode.Should().Be(400);
        }

        [Fact]
        public void Decrypt_ValidRequest_ReturnsOkResult()
        {
            // Arrange
            var request = new DecryptionRequest
            {
                CipherText = new byte[] { 1, 2, 3 },
                Key = new byte[32], // 256-bit key
                Nonce = new byte[] { 4, 5, 6, 7, 8, 9, 10, 11, 12 },
                Tag = new byte[] { 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28 }
            };
            var decryptedText = "Hello, AES-GCM!";

            _mockAesGcmService
                .Setup(s => s.Decrypt(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .Returns(decryptedText);

            // Act
            var result = _controller.Decrypt(request);

            // Assert
            var okResult = result as OkObjectResult;
            okResult.Should().NotBeNull();
            okResult.StatusCode.Should().Be(200);
            var response = okResult.Value as dynamic;
            ((string)response.DecryptedText).Should().Be(decryptedText);
        }

        [Fact]
        public void Decrypt_InvalidRequest_ReturnsBadRequest()
        {
            // Arrange
            _controller.ModelState.AddModelError("CipherText", "Required");

            var request = new DecryptionRequest
            {
                CipherText = null,
                Key = new byte[32], // 256-bit key
                Nonce = new byte[] { 4, 5, 6, 7, 8, 9, 10, 11, 12 },
                Tag = new byte[] { 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28 }
            };

            // Act
            var result = _controller.Decrypt(request);

            // Assert
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Should().NotBeNull();
            badRequestResult.StatusCode.Should().Be(400);
        }

        [Fact]
        public void Decrypt_CryptographicException_ReturnsBadRequest()
        {
            // Arrange
            var request = new DecryptionRequest
            {
                CipherText = new byte[] { 1, 2, 3 },
                Key = new byte[32], // 256-bit key
                Nonce = new byte[] { 4, 5, 6, 7, 8, 9, 10, 11, 12 },
                Tag = new byte[] { 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28 }
            };

            _mockAesGcmService
                .Setup(s => s.Decrypt(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .Throws(new CryptographicException("Decryption failed"));

            // Act
            var result = _controller.Decrypt(request);

            // Assert
            var badRequestResult = result as BadRequestObjectResult;
            badRequestResult.Should().NotBeNull();
            badRequestResult.StatusCode.Should().Be(400);
            var response = badRequestResult.Value as dynamic;
            ((string)response.Message).Should().Contain("Decryption failed");
        }
    }
}

