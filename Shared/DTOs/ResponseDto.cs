namespace Shared.DTOs
{
    public class ResponseDto
    {
        public object? Result { get; set; } = new object();
        public bool isSuccess { get; set; } = false;
        public string Message { get; set; } = string.Empty;
    }
}
