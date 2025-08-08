using System.ComponentModel.DataAnnotations;

namespace TrueTarot_API.DTOs.Auth
{
    public class ChangePasswordDto
    {
        [Required(ErrorMessage = "Mevcut �ifre gereklidir")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Yeni �ifre gereklidir")]
        [MinLength(6, ErrorMessage = "�ifre en az 6 karakter olmal�d�r")]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "�ifre tekrar� gereklidir")]
        [Compare("NewPassword", ErrorMessage = "Yeni �ifreler e�le�miyor")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}