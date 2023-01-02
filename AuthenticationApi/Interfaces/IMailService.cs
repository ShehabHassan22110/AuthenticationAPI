namespace AuthenticationApi.Interfaces
{
    public interface IMailService
    {
        Task SendEmailAsync(string ToEmail , string subject , string content);
    }
}
