using Shared.Enums;
using System.Text.Json.Serialization;

namespace AuthService.Models
{
    public class AuthLog
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public AuthEventType EventType { get; set; } = AuthEventType.Login;

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public bool Success { get; set; } = true;
        public string? FailureReason { get; set; }
        public string? IpAddress { get; set; }
    }
}
