using System.Security.Cryptography;

namespace VerifyEmailForgotPassword.Services.UserService
{
    public class UserService : IUserService
    {
        private readonly DataContext _context;

        public UserService(DataContext context)
        {
            _context = context;
        }

        public async Task<ServiceResponse<string>> Login(string email, string password)
        {
            var response = new ServiceResponse<string>();
            var user = await _context.Users.FirstOrDefaultAsync(
                u => u.Email.ToLower() == email.ToLower());
            if (user == null)
            {
                response.Success = false;
                response.Message = "User not found.";
            }
            else if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
            {
                response.Success = false;
                response.Message = "Wrong password.";
            }
            else if (user.VerifiedAt == null)
            {
                response.Success = false;
                response.Message = "User not verified.";
            }
            else
            {
                response.Data = $"Welcome back {user.Email}!";
            }
            return response;
        }

        public async Task<ServiceResponse<int>> Register(User user, string password)
        {
            if (await _context.Users.AnyAsync(u => u.Email.ToLower() == user.Email.ToLower()))
            {
                return new ServiceResponse<int>
                {
                    Success = false,
                    Message = "User already exists."
                };
            }
            CreatePasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.VerificationToken = CreateRandomToken();

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new ServiceResponse<int>
            {
                Data = user.Id,
                Message = "Registration successful"
            };
        }

        private void CreatePasswordHash(
            string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(
            string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateRandomToken()
        {
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
            if (_context.Users.Any(u => u.PasswordResetToken == token))
            {
                CreateRandomToken();
            }
            return token;
        }

        public async Task<ServiceResponse<bool>> Verify(string token)
        {
            var response = new ServiceResponse<bool>();
            var user = await _context.Users.FirstOrDefaultAsync(
                u => u.VerificationToken == token);
            if (user == null)
            {
                response.Data = false;
                response.Success = false;
                response.Message = "Verification failed";
            }
            else
            {
                user.VerifiedAt = DateTime.Now;
                response.Data = true;
                response.Message = "Verification successful";
                await _context.SaveChangesAsync();
            }
            return response;
        }

        public async Task<ServiceResponse<string>> ForgotPassword(string email)
        {
            var response = new ServiceResponse<string>();
            var user = await _context.Users.FirstOrDefaultAsync(
                u => u.Email == email);
            if (user == null)
            {
                response.Success = false;
                response.Message = "User not found.";
            }
            else
            {
                user.PasswordResetToken = CreateRandomToken();
                user.ResetTokenExpires = DateTime.Now.AddDays(1);
                await _context.SaveChangesAsync();
                response.Data = user.PasswordResetToken;
            }
            return response;
        }

        public async Task<ServiceResponse<int>> ResetPassword(string token, string password)
        {
            var response = new ServiceResponse<int>();
            var user = await _context.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == token);
            if(user == null || user.ResetTokenExpires < DateTime.Now)
            {
                response.Success = false;
                response.Message = "User not found or Reset token expired";
            }
            else
            {
                CreatePasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);
                user.PasswordHash = passwordHash;
                user.PasswordSalt = passwordSalt;
                user.PasswordResetToken = null;
                user.ResetTokenExpires = null;

                response.Data = user.Id;
                response.Message = "Password successfully reset.";
                await _context.SaveChangesAsync();
            }
            return response;
        }
    }
}
