using System.Text.Json.Serialization;

namespace Shared.Enums
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum AuthEventType
    {
        Login,
        Logout,
        TokenIssued,
        PasswordReset,
        AccountLocked
    }
}
