using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TrueTarot_API.DTOs.Auth;
using TrueTarot_API.Services.Interfaces;

namespace TrueTarot_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Yeni kullanýcý kaydý
        /// </summary>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
        {
            _logger.LogInformation("Register attempt for email: {Email}", request.Email);
            
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Register ModelState invalid for email: {Email}", request.Email);
                return BadRequest(ModelState);
            }

            try
            {
                var result = await _authService.RegisterAsync(request);
                if (result == null)
                {
                    _logger.LogWarning("Register failed - email already exists: {Email}", request.Email);
                    return Conflict(new { message = "Bu email adresi zaten kullanýmda" });
                }

                _logger.LogInformation("Register successful for email: {Email}", request.Email);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Register error for email: {Email}", request.Email);
                return StatusCode(500, new { message = "Kayýt iþlemi sýrasýnda hata oluþtu", error = ex.Message });
            }
        }

        /// <summary>
        /// Kullanýcý giriþi
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
            _logger.LogInformation("Login attempt for email: {Email}", request.Email);
            
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Login ModelState invalid for email: {Email}", request.Email);
                return BadRequest(ModelState);
            }

            try
            {
                var result = await _authService.LoginAsync(request);
                if (result == null)
                {
                    _logger.LogWarning("Login failed for email: {Email}", request.Email);
                    return Unauthorized(new { message = "Email veya þifre hatalý", debug = $"Email: {request.Email}" });
                }

                _logger.LogInformation("Login successful for email: {Email}", request.Email);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error for email: {Email}", request.Email);
                return StatusCode(500, new { message = "Giriþ sýrasýnda hata oluþtu", error = ex.Message });
            }
        }

        /// <summary>
        /// Token yenileme
        /// </summary>
        [HttpPost("refresh-token")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var result = await _authService.RefreshTokenAsync(request.RefreshToken);
                if (result == null)
                    return Unauthorized(new { message = "Geçersiz refresh token" });

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token yenileme hatasý");
                return StatusCode(500, new { message = "Token yenileme hatasý" });
            }
        }

        /// <summary>
        /// Çýkýþ iþlemi
        /// </summary>
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequestDto request)
        {
            try
            {
                var result = await _authService.RevokeTokenAsync(request.RefreshToken);
                if (!result)
                    return BadRequest(new { message = "Geçersiz token" });

                return Ok(new { message = "Çýkýþ baþarýlý" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Çýkýþ hatasý");
                return StatusCode(500, new { message = "Çýkýþ sýrasýnda hata oluþtu" });
            }
        }

        /// <summary>
        /// Kullanýcý bilgileri
        /// </summary>
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            try
            {
                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized();

                var userProfile = await _authService.GetUserProfileAsync(userId);
                if (userProfile == null)
                    return NotFound(new { message = "Kullanýcý bulunamadý" });

                return Ok(userProfile);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Kullanýcý bilgileri hatasý");
                return StatusCode(500, new { message = "Kullanýcý bilgileri alýnamadý" });
            }
        }

        /// <summary>
        /// Kullanýcý profilini güncelle
        /// </summary>
        [HttpPut("profile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized();

                var result = await _authService.UpdateProfileAsync(userId, request);
                if (result == null)
                    return BadRequest(new { message = "Profil güncellenemedi. Email adresi baþka bir kullanýcý tarafýndan kullanýlýyor olabilir." });

                _logger.LogInformation("Profil güncellendi: {UserId}", userId);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profil güncelleme hatasý: {UserId}", User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value);
                return StatusCode(500, new { message = "Profil güncellenirken hata oluþtu" });
            }
        }

        /// <summary>
        /// Þifre deðiþtir
        /// </summary>
        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized();

                var result = await _authService.ChangePasswordAsync(userId, request);
                if (!result)
                    return BadRequest(new { message = "Þifre deðiþtirilemedi. Mevcut þifrenizi kontrol edin." });

                _logger.LogInformation("Þifre deðiþtirildi: {UserId}", userId);
                return Ok(new { message = "Þifre baþarýyla deðiþtirildi" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Þifre deðiþtirme hatasý: {UserId}", User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value);
                return StatusCode(500, new { message = "Þifre deðiþtirme sýrasýnda hata oluþtu" });
            }
        }
    }
}