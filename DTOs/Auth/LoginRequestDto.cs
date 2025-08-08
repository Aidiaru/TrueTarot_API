using System.ComponentModel.DataAnnotations;

namespace TrueTarot_API.DTOs.Auth
{
    public class LoginRequestDto
    {
        [Required(ErrorMessage = "Email adresi gereklidir")]
        [EmailAddress(ErrorMessage = "Geçerli bir email adresi giriniz")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Þifre gereklidir")]
        public string Password { get; set; } = string.Empty;
    }
}