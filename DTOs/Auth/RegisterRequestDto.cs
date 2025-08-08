using System.ComponentModel.DataAnnotations;

namespace TrueTarot_API.DTOs.Auth
{
    public class RegisterRequestDto
    {
        [Required(ErrorMessage = "Email adresi gereklidir")]
        [EmailAddress(ErrorMessage = "Ge�erli bir email adresi giriniz")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "�ifre gereklidir")]
        [MinLength(6, ErrorMessage = "�ifre en az 6 karakter olmal�d�r")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "�ifre tekrar� gereklidir")]
        [Compare("Password", ErrorMessage = "�ifreler e�le�miyor")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Ad gereklidir")]
        [MaxLength(50, ErrorMessage = "Ad en fazla 50 karakter olabilir")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Soyad gereklidir")]
        [MaxLength(50, ErrorMessage = "Soyad en fazla 50 karakter olabilir")]
        public string LastName { get; set; } = string.Empty;
    }
}