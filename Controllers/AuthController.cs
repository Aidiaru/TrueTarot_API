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
        /// Yeni kullan�c� kayd�
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
                    return Conflict(new { message = "Bu email adresi zaten kullan�mda" });
                }

                _logger.LogInformation("Register successful for email: {Email}", request.Email);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Register error for email: {Email}", request.Email);
                return StatusCode(500, new { message = "Kay�t i�lemi s�ras�nda hata olu�tu", error = ex.Message });
            }
        }

        /// <summary>
        /// Kullan�c� giri�i
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
                    return Unauthorized(new { message = "Email veya �ifre hatal�", debug = $"Email: {request.Email}" });
                }

                _logger.LogInformation("Login successful for email: {Email}", request.Email);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error for email: {Email}", request.Email);
                return StatusCode(500, new { message = "Giri� s�ras�nda hata olu�tu", error = ex.Message });
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
                    return Unauthorized(new { message = "Ge�ersiz refresh token" });

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token yenileme hatas�");
                return StatusCode(500, new { message = "Token yenileme hatas�" });
            }
        }

        /// <summary>
        /// ��k�� i�lemi
        /// </summary>
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequestDto request)
        {
            try
            {
                var result = await _authService.RevokeTokenAsync(request.RefreshToken);
                if (!result)
                    return BadRequest(new { message = "Ge�ersiz token" });

                return Ok(new { message = "��k�� ba�ar�l�" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "��k�� hatas�");
                return StatusCode(500, new { message = "��k�� s�ras�nda hata olu�tu" });
            }
        }

        /// <summary>
        /// Kullan�c� bilgileri
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
                    return NotFound(new { message = "Kullan�c� bulunamad�" });

                return Ok(userProfile);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Kullan�c� bilgileri hatas�");
                return StatusCode(500, new { message = "Kullan�c� bilgileri al�namad�" });
            }
        }

        /// <summary>
        /// Kullan�c� profilini g�ncelle
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
                    return BadRequest(new { message = "Profil g�ncellenemedi. Email adresi ba�ka bir kullan�c� taraf�ndan kullan�l�yor olabilir." });

                _logger.LogInformation("Profil g�ncellendi: {UserId}", userId);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Profil g�ncelleme hatas�: {UserId}", User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value);
                return StatusCode(500, new { message = "Profil g�ncellenirken hata olu�tu" });
            }
        }

        /// <summary>
        /// �ifre de�i�tir
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
                    return BadRequest(new { message = "�ifre de�i�tirilemedi. Mevcut �ifrenizi kontrol edin." });

                _logger.LogInformation("�ifre de�i�tirildi: {UserId}", userId);
                return Ok(new { message = "�ifre ba�ar�yla de�i�tirildi" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "�ifre de�i�tirme hatas�: {UserId}", User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value);
                return StatusCode(500, new { message = "�ifre de�i�tirme s�ras�nda hata olu�tu" });
            }
        }
    }
}