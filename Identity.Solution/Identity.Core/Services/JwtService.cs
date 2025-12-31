using Identity.Core.Domain.IdentityEntities;
using Identity.Core.DTO;
using Identity.Core.ServiceContracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.Core.Services
{
    public class JwtService : IjwtService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        public JwtService(IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;

        }

        public async Task<AuthenticationResponse> CreateJwtToken(ApplicationUser user)
        {
            DateTime expiration = DateTime.UtcNow.AddMinutes(
                Convert.ToDouble(_configuration["Jwt:EXPIRATION_MINUTES"])
            );

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(
                    JwtRegisteredClaimNames.Iat,
                    DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64
                ),


                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.PersonName ?? string.Empty),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty)
            };

            // =====  ADD ROLES =====
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var securityKey =
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)
                );

            var signingCredentials =
                new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var tokenGenerator = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: expiration,
                signingCredentials: signingCredentials
            );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenGenerator);

            return new AuthenticationResponse
            {
                AccessToken = token,
                Email = user.Email!,
                PersonName = user.PersonName!,
                UserType = user.UserType,
                Expiration = expiration,
                RefreshToken = GenerateRefreshToken(),
                RefreshTokenExpirationDateTime =
                    DateTime.UtcNow.AddMinutes(
                        Convert.ToInt32(_configuration["RefreshToken:EXPIRATION_MINUTES"])
                    )
            };
        }

        private string GenerateRefreshToken()
        {
            byte[] bytes = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        public async Task<ClaimsPrincipal?> GetPrincipalFromJwtToken(string? token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],

                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],

                ValidateIssuerSigningKey = true,
                IssuerSigningKey =
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)
                    ),

                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            ClaimsPrincipal principal =
                tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                jwtSecurityToken.Header.Alg != SecurityAlgorithms.HmacSha256)
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
    }
}
