using AuthenticationJwtExample.AuthModels;
using AuthenticationJwtExample.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthenticationJwtExample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User(); // add static to save between requests

        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration) { 
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserDto userDto)
        {
            CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = userDto.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserDto userDto)
        {
            //retrieve user domain object from repo (User with hash and salt) to check if username in db
            //
            if (user.UserName != userDto.Username)
            {
                return BadRequest("User not found");
            }
            if (VerifyPasswordHash(userDto.Password, user.PasswordHash, user.PasswordSalt) == false)
            {
                return BadRequest("Incorrect Password");
            }

            var jwt = CreateToken(user);

            return Ok($"Valid User {jwt}");
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            //get hash and salt from user
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                //we compare if stored hashed password is same as entered
                return passwordHash.SequenceEqual(computedHash);
            }
        }

        private string CreateToken(User user) 
        {
            //add claims check user properties
            List<Claim> claims = new List<Claim>() { 
                new Claim(ClaimTypes.Name, user.UserName)
            };

            if (user.UserName != "admin") {
                claims.Add(new Claim(ClaimTypes.Role, "Regular"));
                
            } else {
                claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            }

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Token")));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: credentials);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
