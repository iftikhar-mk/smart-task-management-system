namespace AuthService.DTOs
{
    public class AuthResponseDto
    {
        public AppUserDto User { get; set; } = new();
        public string Token { get; set; } = string.Empty;
    }
}
