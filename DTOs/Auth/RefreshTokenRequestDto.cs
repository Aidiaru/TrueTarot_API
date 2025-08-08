using System.ComponentModel.DataAnnotations;

namespace TrueTarot_API.DTOs.Auth
{
    public class RefreshTokenRequestDto
    {
        [Required(ErrorMessage = "Refresh token gereklidir")]
        public string RefreshToken { get; set; } = string.Empty;
    }
}