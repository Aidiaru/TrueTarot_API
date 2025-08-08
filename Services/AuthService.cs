using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using TrueTarot_API.DTOs.Auth;
using TrueTarot_API.Entities;
using TrueTarot_API.Infrastructure.Configuration;
using TrueTarot_API.Infrastructure.Data;
using TrueTarot_API.Services.Interfaces;

namespace TrueTarot_API.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IMapper _mapper;
        private readonly JwtSettings _jwtSettings;

        public AuthService(
            UserManager<User> userManager,
            ApplicationDbContext context,
            IJwtTokenService jwtTokenService,
            IMapper mapper,
            JwtSettings jwtSettings)
        {
            _userManager = userManager;
            _context = context;
            _jwtTokenService = jwtTokenService;
            _mapper = mapper;
            _jwtSettings = jwtSettings;
        }

        public async Task<AuthResponseDto?> RegisterAsync(RegisterRequestDto request)
        {
            try
            {
                // Check if user already exists - case insensitive
                var existingUser = await _userManager.FindByEmailAsync(request.Email.ToLower());
                if (existingUser != null)
                    return null;

                // Create new user
                var user = new User
                {
                    UserName = request.Email.ToLower(),
                    Email = request.Email.ToLower(),
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    CreatedAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user, request.Password);
                if (!result.Succeeded)
                    return null;

                // Add default role
                await _userManager.AddToRoleAsync(user, "User");

                // Generate tokens
                var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(user);
                var refreshToken = _jwtTokenService.GenerateRefreshToken();

                // Save refresh token
                var refreshTokenEntity = new RefreshToken
                {
                    Token = refreshToken,
                    Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
                    UserId = user.Id,
                    CreatedByIp = "API"
                };

                _context.RefreshTokens.Add(refreshTokenEntity);
                await _context.SaveChangesAsync();

                // AutoMapper kullanarak mapping
                var userDto = _mapper.Map<UserDto>(user);
                userDto.Roles = ["User"]; // Rol manuel olarak atanýyor

                return new AuthResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                    User = userDto
                };
            }
            catch (Exception ex)
            {
                // Log the actual error
                Console.WriteLine($"Register Error: {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}");
                return null;
            }
        }

        public async Task<AuthResponseDto?> LoginAsync(LoginRequestDto request)
        {
            try
            {
                Console.WriteLine($"[DEBUG] Login için email: {request.Email.ToLower()}");
                
                // Kullanýcýyý email ile bulma
                var user = await _userManager.FindByEmailAsync(request.Email.ToLower());
                
                // Kullanýcý bulundu mu?
                if (user == null)
                {
                    Console.WriteLine($"[DEBUG] Kullanýcý bulunamadý: {request.Email.ToLower()}");
                    return null;
                }
                
                Console.WriteLine($"[DEBUG] Kullanýcý bulundu: {user.Id}, {user.Email}");
                
                // Þifre kontrolü
                var passwordCheck = await _userManager.CheckPasswordAsync(user, request.Password);
                Console.WriteLine($"[DEBUG] Þifre doðrulama: {passwordCheck}");
                
                if (!passwordCheck)
                {
                    Console.WriteLine($"[DEBUG] Þifre doðrulamasý baþarýsýz: {request.Email.ToLower()}");
                    return null;
                }

                // Generate tokens
                var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(user);
                var refreshToken = _jwtTokenService.GenerateRefreshToken();

                // Revoke old refresh tokens - IsActive yerine doðrudan koþullarý kullan
                var oldTokens = await _context.RefreshTokens
                    .Where(rt => rt.UserId == user.Id && rt.Revoked == null && rt.Expires > DateTime.UtcNow)
                    .ToListAsync();

                foreach (var oldToken in oldTokens)
                {
                    oldToken.Revoked = DateTime.UtcNow;
                    oldToken.RevokedByIp = "API";
                }

                // Save new refresh token
                var refreshTokenEntity = new RefreshToken
                {
                    Token = refreshToken,
                    Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
                    UserId = user.Id,
                    CreatedByIp = "API"
                };

                _context.RefreshTokens.Add(refreshTokenEntity);
                await _context.SaveChangesAsync();

                // AutoMapper kullanarak mapping
                var roles = await _userManager.GetRolesAsync(user);
                Console.WriteLine($"[DEBUG] Kullanýcý rolleri: {string.Join(", ", roles)}");
                
                var userDto = _mapper.Map<UserDto>(user);
                userDto.Roles = roles.ToList(); // Roller manuel olarak atanýyor

                return new AuthResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                    User = userDto
                };
            }
            catch (Exception ex)
            {
                // Log the actual error
                Console.WriteLine($"[ERROR] Login Error: {ex.Message}");
                Console.WriteLine($"[ERROR] Stack Trace: {ex.StackTrace}");
                return null;
            }
        }

        public async Task<AuthResponseDto?> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                // IsActive yerine doðrudan koþullarý kullan
                var tokenEntity = await _context.RefreshTokens
                    .Include(rt => rt.User)
                    .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.Revoked == null && rt.Expires > DateTime.UtcNow);

                if (tokenEntity == null)
                    return null;

                // Revoke old token
                tokenEntity.Revoked = DateTime.UtcNow;
                tokenEntity.RevokedByIp = "API";

                // Generate new tokens
                var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(tokenEntity.User);
                var newRefreshToken = _jwtTokenService.GenerateRefreshToken();

                // Save new refresh token
                var newRefreshTokenEntity = new RefreshToken
                {
                    Token = newRefreshToken,
                    Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
                    UserId = tokenEntity.UserId,
                    CreatedByIp = "API"
                };

                _context.RefreshTokens.Add(newRefreshTokenEntity);
                await _context.SaveChangesAsync();

                // AutoMapper kullanarak mapping
                var roles = await _userManager.GetRolesAsync(tokenEntity.User);
                var userDto = _mapper.Map<UserDto>(tokenEntity.User);
                userDto.Roles = roles.ToList(); // Roller manuel olarak atanýyor

                return new AuthResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = newRefreshToken,
                    Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                    User = userDto
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RefreshToken Error: {ex.Message}");
                return null;
            }
        }

        public async Task<bool> RevokeTokenAsync(string refreshToken)
        {
            // IsActive yerine doðrudan koþullarý kullan
            var tokenEntity = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.Revoked == null && rt.Expires > DateTime.UtcNow);

            if (tokenEntity == null)
                return false;

            tokenEntity.Revoked = DateTime.UtcNow;
            tokenEntity.RevokedByIp = "API";

            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<UserDto?> UpdateProfileAsync(string userId, UpdateProfileDto request)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return null;

            // Check if email is being changed and if it's already taken by another user
            if (user.Email != request.Email.ToLower())
            {
                var existingUser = await _userManager.FindByEmailAsync(request.Email.ToLower());
                if (existingUser != null && existingUser.Id != userId)
                    return null; // Email already taken
            }

            // Update user properties
            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.Email = request.Email.ToLower();
            user.UserName = request.Email.ToLower();
            user.UpdatedAt = DateTime.UtcNow;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return null;

            // AutoMapper kullanarak mapping
            var roles = await _userManager.GetRolesAsync(user);
            var userDto = _mapper.Map<UserDto>(user);
            userDto.Roles = roles.ToList(); // Roller manuel olarak atanýyor

            return userDto;
        }

        public async Task<bool> ChangePasswordAsync(string userId, ChangePasswordDto request)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return false;

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            return result.Succeeded;
        }

        public async Task<UserDto?> GetUserProfileAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return null;

            // AutoMapper kullanarak mapping
            var roles = await _userManager.GetRolesAsync(user);
            var userDto = _mapper.Map<UserDto>(user);
            userDto.Roles = roles.ToList(); // Roller manuel olarak atanýyor

            return userDto;
        }
    }
}