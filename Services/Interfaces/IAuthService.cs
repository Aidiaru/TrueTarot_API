using TrueTarot_API.DTOs.Auth;

namespace TrueTarot_API.Services.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponseDto?> RegisterAsync(RegisterRequestDto request);
        Task<AuthResponseDto?> LoginAsync(LoginRequestDto request);
        Task<AuthResponseDto?> RefreshTokenAsync(string refreshToken);
        Task<bool> RevokeTokenAsync(string refreshToken);
        
        // Yeni method'lar
        Task<UserDto?> UpdateProfileAsync(string userId, UpdateProfileDto request);
        Task<bool> ChangePasswordAsync(string userId, ChangePasswordDto request);
        Task<UserDto?> GetUserProfileAsync(string userId);
    }
}