namespace AuthService.DTOs
{
    public class AuthLogDto
    {
        public Guid Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string EventType { get; set; } = "Login";
        public DateTime Timestamp { get; set; }
        public bool Success { get; set; }
        public string? FailureReason { get; set; }
        public string? IpAddress { get; set; }
    }
}