using TrueTarot_API.Entities;

namespace TrueTarot_API.Services.Interfaces
{
    public interface IJwtTokenService
    {
        Task<string> GenerateAccessTokenAsync(User user);
        string GenerateRefreshToken();
        Task<bool> ValidateTokenAsync(string token);
    }
}