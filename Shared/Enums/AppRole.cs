using System.Text.Json.Serialization;

namespace Shared.Enums
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum AppRole
    {
        User,
        Admin,
        Moderator,
        Manager
    }
}