using AuthenticationApi.Helper;
using AuthenticationApi.Models;
using static AuthenticationApi.Models.ResetPasswordModel;

namespace AuthenticationApi.Services.Interfaces
{
    public interface IUserService
    {
        Task<UserManagerResponse> RegisterUserAsync(RegisterModel model);
        Task<UserManagerResponse> LoginUserAsync(LoginModel model);
        Task<UserManagerResponse> ConfirmEmailAsync(string userId , string token);
        Task<UserManagerResponse> ForgetPasswordAsync(string Email);
        Task<UserManagerResponse> ResetPasswordAsync(ResetPasswordModel model);

    }
}
