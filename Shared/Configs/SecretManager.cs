using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;

namespace Shared.Configs
{
    public class SecretManager
    {
        private readonly IConfiguration _config;
        private readonly bool _useAzureVault;
        private readonly SecretClient? _vaultClient;

        public SecretManager(IConfiguration config)
        {
            _config = config;
            _useAzureVault = bool.TryParse(config["UseAzureKeyVault"], out var useVault) && useVault;

            if (_useAzureVault)
            {
                var vaultUri = config["AzureKeyVault:VaultUri"];
                if (!string.IsNullOrEmpty(vaultUri))
                {
                    _vaultClient = new SecretClient(new Uri(vaultUri), new DefaultAzureCredential());
                }
                else
                {
                    throw new InvalidOperationException("Azure Key Vault URI missing from configuration.");
                }
            }
        }

        public bool SetAuthToken(string value = "")
        {
            try
            {
                if (_useAzureVault && _vaultClient != null)
                {
                    KeyVaultSecret secret = _vaultClient.SetSecret(AzureSecrets.AuthToken, value);
                    return secret.Value == value;
                }
                else
                {
                    Environment.SetEnvironmentVariable("AuthToken", value, EnvironmentVariableTarget.User);
                    return true;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error saving secret '{value}': {ex.InnerException?.Message ?? ex.Message}");
            }
        }

        public string GetAuthToken()
        {
            return GetSecret(AzureSecrets.AuthToken);
        }

        public string GetSecret(string key)
        {
            try
            {
                if (_useAzureVault && _vaultClient != null)
                {
                    KeyVaultSecret secret = _vaultClient.GetSecret(key);
                    return secret.Value;
                }
                else
                {
                    var value = _config[key] ?? Environment.GetEnvironmentVariable(key, EnvironmentVariableTarget.User);
                    if (string.IsNullOrWhiteSpace(value))
                        throw new Exception($"Secret '{key}' not found in environment or configuration.");

                    return value;
                }
            }
            catch (Exception ex)
            {
                // Optional: Add logging here
                throw new Exception($"Error retrieving secret '{key}': {ex.InnerException?.Message ?? ex.Message}");
            }
        }
    }
}
