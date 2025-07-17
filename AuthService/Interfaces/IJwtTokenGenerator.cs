using AuthService.DTOs;
using AuthService.Models;

namespace AuthService.Interfaces
{
    public interface IJwtTokenGenerator
    {
        Task<(string Token, AppUserDto User)> GenerateTokenAsync(AppUser user);
    }
}
