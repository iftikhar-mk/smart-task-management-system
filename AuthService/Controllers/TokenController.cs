using AuthService.Data;
using AuthService.DTOs;
using AuthService.Interfaces;
using AuthService.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Shared.Configs;
using Shared.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/token")]
    public class TokenController : ControllerBase
    {
        private readonly IJwtTokenGenerator _jwtTokenGenerator;
        private readonly IMapper _mapper;
        private readonly ITokenProvider _tokenProvider;
        private readonly UserManager<AppUser> _userManager;
        private readonly SecretManager _secretManager;

        public TokenController(IJwtTokenGenerator jwtTokenGenerator, IMapper mapper, ITokenProvider tokenProvider, UserManager<AppUser> userManager, SecretManager secretManager)
        {
            _jwtTokenGenerator = jwtTokenGenerator;
            _mapper = mapper;
            _tokenProvider = tokenProvider;
            _userManager = userManager;
            _secretManager = secretManager;
        }

        /// <summary>
        /// Refreshes an expired access token using a valid refresh token.
        /// </summary>
        [Authorize]
        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] string refreshToken)
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userId))
                {
                    return Unauthorized(new ResponseDto { Message = "User ID not found in token." });
                }

                AppUser user = _userManager.Users.FirstOrDefault(u => u.Id == userId);
                var savedToken = "";

                //This is a stub. Will be replaced with actual TokenProvider
                //savedToken = await _tokenProvider.GetTokenForUser(userId);
                savedToken = _tokenProvider.GetToken();

                if (refreshToken != savedToken)
                    return Unauthorized(new ResponseDto { Message = "Invalid refresh token." });

                // Issue new token
                var (token, userDto) = _jwtTokenGenerator.GenerateTokenAsync(user).GetAwaiter().GetResult();

                var dto = new AuthResponseDto
                {
                    User = userDto,
                    Token = token
                };

                return Ok(new ResponseDto
                {
                    Result = dto,
                    isSuccess = true,
                    Message = "Token refreshed."
                });
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(new ResponseDto
                {
                    Message = $"Error refreshing token: {ex.InnerException?.Message ?? ex.Message}"
                });
            }
        }

        /// <summary>
        /// Validates a JWT token and returns its decoded claims.
        /// </summary>
        [AllowAnonymous]
        [HttpPost("validate")]
        public IActionResult ValidateToken([FromBody] string token)
        {
            var response = new ResponseDto();
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_secretManager.GetSecret(AzureSecrets.JwtKey));

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidIssuer = _secretManager.GetSecret(AzureSecrets.JwtIssuer),
                ValidAudience = _secretManager.GetSecret(AzureSecrets.JwtAudience),
                ClockSkew = TimeSpan.Zero // No leeway for token expiry
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                if (validatedToken is JwtSecurityToken jwt &&
                    !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    response.Message = "Invalid token algorithm";
                    return BadRequest(response);
                }

                var claims = principal.Claims.Select(c => new { c.Type, c.Value }).ToList();

                response.Result = claims;
                response.isSuccess = true;
                response.Message = "Token is valid.";
                return Ok(response);
            }
            catch (SecurityTokenExpiredException)
            {
                response.Message = "Token has expired.";
                return Unauthorized(response);
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                response.Message = "Invalid token signature.";
                return Unauthorized(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Token validation failed: {ex.InnerException?.Message ?? ex.Message}";
                return BadRequest(response);
            }
        }
    }
}
