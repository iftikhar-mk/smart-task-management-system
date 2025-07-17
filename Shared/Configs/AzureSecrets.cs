namespace Shared.Configs
{
    public static class AzureSecrets
    {
        // JWT-related secrets
        public const string JwtKey = "JwtKey";
        public const string JwtIssuer = "JwtIssuer";
        public const string JwtAudience = "JwtAudience";

        // Actual Token
        public const string AuthToken = "AuthToken";

        // Database secrets
        public const string AuthDbConnectionString = "AuthDbConnectionString";
        public const string TaskDbConnectionString = "TaskDbConnectionString";
        public const string NotificationDbConnectionString = "NotificationDbConnectionString";
        public const string ReminderDbConnectionString = "ReminderDbConnectionString";
        public const string GatewayDbConnectionString = "GatewayDbConnectionString"; // optional

        // External login providers' secrets
        public const string GoogleClientId = "GoogleClientId";
        public const string GoogleClientSecret = "GoogleClientSecret";
        public const string MicrosoftClientId = "MicrosoftClientId";
        public const string MicrosoftClientSecret = "MicrosoftClientSecret";
        public const string GitHubClientId = "GitHubClientId";
        public const string GitHubClientSecret = "GitHubClientSecret";
        public const string FacebookClientId = "FacebookClientId";
        public const string FacebookClientSecret = "FacebookClientSecret";

        // Identity secrets
        public const string IdentitySalt = "IdentitySalt";

        // Notification secrets
        public const string NotificationKey = "NotificationServiceKey";

        // Reminder secrets
        public const string ReminderInterval = "ReminderIntervalMinutes";

        // ApiGateway secrets
        public const string GatewayRateLimit = "GatewayRateLimit";

        // ToDo: Add more secrets as needed for other services
    }

}
