using System.ComponentModel.DataAnnotations;

namespace TrueTarot_API.DTOs.Auth
{
    public class ChangePasswordDto
    {
        [Required(ErrorMessage = "Mevcut þifre gereklidir")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Yeni þifre gereklidir")]
        [MinLength(6, ErrorMessage = "Þifre en az 6 karakter olmalýdýr")]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Þifre tekrarý gereklidir")]
        [Compare("NewPassword", ErrorMessage = "Yeni þifreler eþleþmiyor")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}