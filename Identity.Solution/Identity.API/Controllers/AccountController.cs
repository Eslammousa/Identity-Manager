using Identity.Core.Domain.IdentityEntities;
using Identity.Core.DTO;
using Identity.Core.ServiceContracts;
using Identity.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Identity.API.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IjwtService _jwtService;


        public AccountController(UserManager<ApplicationUser> userManager , IjwtService ijwtService)
        {
            _userManager = userManager;
            _jwtService = ijwtService;
        }

        [HttpPost("register")]
        [Authorize("NotAuthorized")]
        public async Task<ActionResult> Register(RegisterDTO registerDTO)
        {
            // 1. Validation

            if (!ModelState.IsValid)
            {
                string errorMessage = string.Join(" | ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage));
                return BadRequest(errorMessage);
            }


            //2- Create user
            ApplicationUser user = new ApplicationUser()
            {
                Email = registerDTO.Email,
                PhoneNumber = registerDTO.Phone,
                UserName = registerDTO.Email,
                PersonName = registerDTO.PersonName
            };

            IdentityResult result = await _userManager.CreateAsync(user, registerDTO.Password);

            if (result.Succeeded)
            {

                var authenticationResponse = _jwtService.CreateJwtToken(user);
                user.RefreshToken = authenticationResponse.RefreshToken;

                user.RefreshTokenExpirationDateTime = authenticationResponse.RefreshTokenExpirationDateTime;
                await _userManager.UpdateAsync(user);
                return Ok(authenticationResponse);
            }
            else
            {
                string errorMessage = string.Join(" | ", result.Errors.Select(e => e.Description)); //error1 | error2
                return BadRequest(errorMessage);
            }
        }

        [HttpPost("login")]
        [Authorize("NotAuthorized")]
        public async Task<IActionResult> PostLogin(LoginDTO loginDTO)
        {
            //Validation
            if (!ModelState.IsValid)
            {
                string errorMessage = string.Join(" | ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage));
                return BadRequest(errorMessage);
            }

            // 2. Find user by email
            var user = await _userManager.FindByEmailAsync(loginDTO.Email);
            if (user == null)
            {
                return Unauthorized("Invalid email or password");
            }

            // 3 - Check password
            var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginDTO.Password);
            if (!isPasswordValid)
                return Unauthorized("Invalid email or password");


            var authenticationResponse = _jwtService.CreateJwtToken(user);

            user.RefreshToken = authenticationResponse.RefreshToken;

            user.RefreshTokenExpirationDateTime = authenticationResponse.RefreshTokenExpirationDateTime;
            await _userManager.UpdateAsync(user);

            return Ok(authenticationResponse);


        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> PostLogout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized(new { message = "Invalid token" });


            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized(new { message = "User not found" });

            // 3. Check if already logged out (optional)
            if (string.IsNullOrEmpty(user.RefreshToken))
            {
                return Ok(new { message = "Already logged out" });
            }

            user.RefreshToken = null;
            user.RefreshTokenExpirationDateTime = default;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description);
                return BadRequest(new { message = "Logout failed", errors });
            }
             
            return Ok(new { message = "Logged out successfully" });
        }

        [AllowAnonymous]
        [HttpPost("generate-new-jwt-token")]
        public async Task<IActionResult> GenerateNewAccessToken(TokenModel tokenModel)
        {
            if (tokenModel == null ||
                string.IsNullOrWhiteSpace(tokenModel.AccessToken) ||
                string.IsNullOrWhiteSpace(tokenModel.RefreshToken))
            {
                return BadRequest("Invalid client request");
            }

            ClaimsPrincipal? principal =
                _jwtService.GetPrincipalFromJwtToken(tokenModel.AccessToken);

            if (principal == null)
                return Unauthorized("Invalid access token");

            string? userId =
                principal.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
                return Unauthorized("Invalid token claims");

            ApplicationUser? user =
                await _userManager.FindByIdAsync(userId);

            if (user == null ||
                user.RefreshToken != tokenModel.RefreshToken ||
                user.RefreshTokenExpirationDateTime <= DateTime.UtcNow)
            {
                return Unauthorized("Invalid refresh token");
            }

            AuthenticationResponse authenticationResponse =
                _jwtService.CreateJwtToken(user);

            user.RefreshToken = authenticationResponse.RefreshToken;
            user.RefreshTokenExpirationDateTime =
                authenticationResponse.RefreshTokenExpirationDateTime;

            await _userManager.UpdateAsync(user);

            return Ok(authenticationResponse);
        }


        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> IsEmailAlreadyRegistered(string email)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return Ok(true);
            }
            else
            {
                return Ok(false);
            }
        }
    }
}
