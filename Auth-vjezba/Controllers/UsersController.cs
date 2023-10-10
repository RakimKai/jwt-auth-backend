using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Auth_vjezba.Data;
using Auth_vjezba.Models;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System;

namespace Auth_vjezba.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly ApiContext _context;
        private IConfiguration _config;
        private const string SecretKey = "Dp9z2GjW8QaV7zR6TgKx5sBc3FmQ6zA1Lp7yHtG3Dv6zXp2jUs8wRhN2CgH5kFt9";
        private readonly SymmetricSecurityKey _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));

        public UsersController(ApiContext context, IConfiguration config)
        {
            _context = context;
            _config =  config;
        }
        public static string GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] saltBytes = new byte[16]; 
                rng.GetBytes(saltBytes);
                return Convert.ToBase64String(saltBytes);
            }

        }
        public static string HashPassword(string password, string salt)
        {
            int iterations = 1000; 
            byte[] saltBytes = Convert.FromBase64String(salt);

            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, saltBytes, iterations))
            {
                byte[] hashBytes = rfc2898DeriveBytes.GetBytes(256 / 8);  
                return Convert.ToBase64String(hashBytes);
            }
        }
        private object GenerateAccessToken(Users user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credendtials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,user.Username),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.Role,user.Role),
            };

            var token = new JwtSecurityToken(_config["Jwt:Issuer"], _config["Jwt:Audience"], claims, expires: DateTime.Now.AddMinutes(15), signingCredentials: credendtials);

            return new JwtSecurityTokenHandler().WriteToken(token);

        }


        [HttpPost("/post")]
        public JsonResult Post([FromBody] Users user)
        {
            var inValidEmail = _context.Users.Any(u => u.Email == user.Email);
            var inValidUsername = _context.Users.Any(u => u.Username == user.Username);

            if (inValidEmail || inValidUsername)
            {
                string infoMessage = inValidEmail && inValidUsername ? "User with this email and username already exists." : inValidEmail ? "User with this email already exists." : inValidUsername ? "User with this username already exists." : string.Empty;
                return new JsonResult(new
                {
                    success = false,
                    message = infoMessage,
                });
            }

            user.Salts = GenerateSalt();
            user.Password = HashPassword(user.Password, user.Salts);
            _context.Users.Add(user);
            var token = GenerateAccessToken(user);
            _context.SaveChanges();
            return new JsonResult(new
            {
                success = true,
                data = user,
                access_token = token,

            });


        }

        [HttpGet("/get")]
        public JsonResult Get(int id)
        {
            var userInDb = _context.Users.FirstOrDefault(u=>u.Id== id);
            if (userInDb != null)
            {

                return new JsonResult(new
                {
                    data = userInDb,
                });
            }
            else
            {
                return new JsonResult(BadRequest("User doesn't exist."));
            }

        }
        [HttpGet("check-username-password")]
        public JsonResult CheckUsername(string username, string password)
        {
            var user = _context.Users.FirstOrDefault(u => u.Username == username);

            if (user != null)
            {
                var hashedPassword = HashPassword(password, user.Salts);
                if (hashedPassword == user.Password)
                {
                    var token = GenerateAccessToken(user);
                    return new JsonResult(new
                    {
                        success = true,
                        access_token = token
                    });
                }
                else
                {
                    return new JsonResult(new
                    {
                        success = false,
                        message = "Incorrect username or password"
                    });
                }
            }
            else
            {

                return new JsonResult(new
                {
                    success = false,
                    message = "Incorrect username or password"
                });
            }
        }

        [HttpPost("validate-token")]
        public IActionResult ValidateToken([FromBody] TokenRequest request)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                tokenHandler.ValidateToken(request.Token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _signingKey,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return Ok(new { isValid = true });
            }
            catch
            {
                return Ok(new { isValid = false });
            }
        }

        
    }
}
