using AuthService.DTOs;
using AuthService.Interfaces;
using AuthService.Models;
using AuthService.Services;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Shared.DTOs;
using Shared.Enums;
using System.Security.Claims;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/external-auth")]
    public class ExternalAuthController : ControllerBase
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly IMapper _mapper;
        private readonly IJwtTokenGenerator _jwtTokenService;

        public ExternalAuthController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, IMapper mapper, IJwtTokenGenerator jwtTokenService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _mapper = mapper;
            _jwtTokenService = jwtTokenService;
        }

        /// <summary>
        /// Lists available external login providers.
        /// </summary>
        [HttpGet("providers")]
        [AllowAnonymous]
        public IActionResult GetProviders()
        {
            var response = new ResponseDto();
            try
            {
                List<string> providers = new List<string>();
                providers = Enum.GetNames<ExternalAuthProvider>().ToList();

                response.Result = providers;
                response.Message = "External providers available.";
                response.isSuccess = true;
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        /// <summary>
        /// Starts the external login process.
        /// </summary>
        [HttpGet("login/{provider}")]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, string? returnUrl = null)
        {
            if (string.IsNullOrEmpty(provider))
                return BadRequest(new ResponseDto() { Message = "No external provider specificed" });

            if (!Enum.TryParse<ExternalAuthProvider>(provider.ToUpper(), true, out var providerEnum))
                return BadRequest(new ResponseDto { Message = "Invalid provider specified" });

            var redirectUrl = Url.Action(nameof(ExternalCallback), "ExternalAuth", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        /// <summary>
        /// Handles the external login callback, creates user if not found.
        /// </summary>
        [HttpGet("callback")]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalCallback(string? returnUrl = null, string? remoteError = null)
        {
            var response = new ResponseDto();

            if (!string.IsNullOrEmpty(remoteError))
            {
                response.Message = $"External provider error: {remoteError}";
                return BadRequest(response);
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                response.Message = "External login info not found.";
                return Unauthorized(response);
            }

            // Try existing login
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            AppUser user;

            if (result.Succeeded)
            {
                user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            }
            else
            {
                // Get email claim
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                if (string.IsNullOrEmpty(email))
                {
                    response.Message = "Email claim not provided by external provider.";
                    return BadRequest(response);
                }

                user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    // Create new user
                    user = new AppUser
                    {
                        UserName = email,
                        Email = email,
                        DisplayName = info.Principal.Identity?.Name ?? "External User"
                    };

                    var createResult = await _userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                    {
                        response.Message = "User creation failed.";
                        response.Result = createResult.Errors;
                        return BadRequest(response);
                    }

                    await _userManager.AddToRoleAsync(user, AppRole.User.ToString());
                }

                await _userManager.AddLoginAsync(user, info);
            }

            // Generate token
            var (token, userDto) = await _jwtTokenService.GenerateTokenAsync(user);

            var authResult = new AuthResponseDto
            {
                User = userDto,
                Token = token
            };

            response.Result = authResult;
            response.isSuccess = true;
            response.Message = "External login successful.";
            return Ok(response);
        }
    }
}