namespace AuthService.DTOs
{
    public class AppUserDto
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public bool IsDisabled { get; set; } = false;
        public List<string> Roles { get; set; } = new();
    }
}