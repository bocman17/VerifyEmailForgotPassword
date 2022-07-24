namespace VerifyEmailForgotPassword.Services.UserService
{
    public interface IUserService
    {
        Task<ServiceResponse<int>> Register(User user, string password);
        Task<ServiceResponse<string>> Login(string email, string password);
        Task<ServiceResponse<bool>> Verify(string token);
        Task<ServiceResponse<string>> ForgotPassword(string email);
        Task<ServiceResponse<int>> ResetPassword(string token, string password);

    }
}
