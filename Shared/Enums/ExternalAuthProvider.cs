using System.Text.Json.Serialization;

namespace Shared.Enums
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ExternalAuthProvider
    {
        GOOGLE,
        MICROSOFT,
        GITHUB,
        FACEBOOK
        // Add more providers as needed
    }
}