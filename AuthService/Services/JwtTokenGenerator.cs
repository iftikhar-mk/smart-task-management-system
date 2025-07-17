using AuthService.DTOs;
using AuthService.Interfaces;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Shared.Configs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthService.Services
{
    public class JwtTokenGenerator: IJwtTokenGenerator
    {
        private readonly SecretManager _secretManager;
        private readonly UserManager<AppUser> _userManager;

        public JwtTokenGenerator(SecretManager secretManager, UserManager<AppUser> userManager)
        {
            _secretManager = secretManager;
            _userManager = userManager;
        }

        public async Task<(string Token, AppUserDto User)> GenerateTokenAsync(AppUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_secretManager.GetSecret(AzureSecrets.JwtKey)));

            var claimList = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.NameId, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                new Claim("DisplayName", user.DisplayName),
            };

            var roles = await _userManager.GetRolesAsync(user);
            claimList.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var audience = _secretManager.GetSecret(AzureSecrets.JwtAudience);
            var issuer = _secretManager.GetSecret(AzureSecrets.JwtIssuer);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = audience,
                Issuer = issuer,
                Subject = new ClaimsIdentity(claimList),
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = creds
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            var userDto = new AppUserDto
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                DisplayName = user.DisplayName,
                Roles = roles.ToList()
            };

            return (tokenString, userDto);
        }
    }
}