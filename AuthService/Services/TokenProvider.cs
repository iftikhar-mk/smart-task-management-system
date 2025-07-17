using AuthService.Interfaces;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Shared.Configs;

namespace AuthService.Services
{
    public class TokenProvider : ITokenProvider
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly SecretManager _secretManager;

        public TokenProvider(IHttpContextAccessor contextAccessor, SecretManager secretManager)
        {
            _contextAccessor = contextAccessor;
            _secretManager = secretManager;
        }

        public void ClearToken()
        {
            _secretManager.SetAuthToken("");
        }

        public string GetToken()
        {
            return _secretManager.GetAuthToken();
        }

        public bool HasToken()
        {
            return !string.IsNullOrEmpty(_secretManager.GetAuthToken());
        }

        public bool SetToken(string token)
        {
            return _secretManager.SetAuthToken(token);
        }
    }
}
