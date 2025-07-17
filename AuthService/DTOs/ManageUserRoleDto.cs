using Shared.Enums;

namespace AuthService.DTOs
{
    public class ManageUserRoleDto
    {
        public string UserId { get; set; } = string.Empty;
        public List<string> Roles { get; set; } = new();
    }
}
