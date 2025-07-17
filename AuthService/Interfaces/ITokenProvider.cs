namespace AuthService.Interfaces
{
    public interface ITokenProvider
    {
        void ClearToken();
        bool SetToken(string token);
        bool HasToken();
        string GetToken();
    }
}
