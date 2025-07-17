namespace AuthService.DTOs
{
    public class SetUserStatusDto
    {
        public string UserId { get; set; }
        public bool IsDisabled { get; set; } // true = enable, false = disable
    }

}
