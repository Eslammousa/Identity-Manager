using Identity.Core.Domain.IdentityEntities;
using Identity.Core.DTO;
using Identity.Core.ServiceContracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Identity.API.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IjwtService _jwtService;


        public AccountController(UserManager<ApplicationUser> userManager, IjwtService ijwtService)
        {
            _userManager = userManager;
            _jwtService = ijwtService;
        }

        [HttpPost("register")]
        [Authorize(policy: "NotAuthorized")]
        public async Task<ActionResult> Register(RegisterDTO registerDTO)
        {

            var user = new ApplicationUser
            {
                Email = registerDTO.Email,
                UserName = registerDTO.Email,
                PhoneNumber = registerDTO.Phone,
                PersonName = registerDTO.PersonName,
                UserType = AppRoles.User 
            };

            var result = await _userManager.CreateAsync(user, registerDTO.Password);

            if (!result.Succeeded)
            {
                var errors = string.Join(" | ",
                    result.Errors.Select(e => e.Description));
                return BadRequest(errors);
            }

            await _userManager.AddToRoleAsync(user, "User");

            var authResponse = await _jwtService.CreateJwtToken(user);

            user.RefreshToken = authResponse.RefreshToken;
            user.RefreshTokenExpirationDateTime =
                authResponse.RefreshTokenExpirationDateTime;

            await _userManager.UpdateAsync(user);

            return Ok(authResponse);
        }


        [HttpPost("login")]
        //[Authorize("NotAuthorized")]
        [AllowAnonymous]

        public async Task<ActionResult> PostLogin(LoginDTO loginDTO)
        {

            var user = await _userManager.FindByEmailAsync(loginDTO.Email);
            if (user == null)
            {
                return Unauthorized("Invalid email or password");
            }

            // 3 - Check password
            var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginDTO.Password);
            if (!isPasswordValid)
                return Unauthorized("Invalid email or password");

            var authenticationResponse = await _jwtService.CreateJwtToken(user);

            user.RefreshToken = authenticationResponse.RefreshToken;

            user.RefreshTokenExpirationDateTime = authenticationResponse.RefreshTokenExpirationDateTime;
            await _userManager.UpdateAsync(user);

            return Ok(authenticationResponse);

        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<ActionResult> PostLogout()
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
        public async Task<ActionResult> GenerateNewAccessToken(TokenModel tokenModel)
        {
            if (tokenModel == null ||
                string.IsNullOrWhiteSpace(tokenModel.AccessToken) ||
                string.IsNullOrWhiteSpace(tokenModel.RefreshToken))
            {
                return BadRequest("Invalid client request");
            }

            ClaimsPrincipal? principal =
               await _jwtService.GetPrincipalFromJwtToken(tokenModel.AccessToken);

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
                await _jwtService.CreateJwtToken(user);

            user.RefreshToken = authenticationResponse.RefreshToken;
            user.RefreshTokenExpirationDateTime =
                authenticationResponse.RefreshTokenExpirationDateTime;

            await _userManager.UpdateAsync(user);

            return Ok(authenticationResponse);
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult> IsEmailAlreadyRegistered(string email)
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


        [Authorize(Roles = AppRoles.Admin)]
        [HttpPut("change-role")]
        public async Task<ActionResult> ChangeUserRole(ChangeUserRoleDTO dto)
        {
            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null) return NotFound();

            var currentRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, currentRoles);
            await _userManager.AddToRoleAsync(user, dto.Role);

            user.UserType = dto.Role;
            await _userManager.UpdateAsync(user);

            return Ok($"Role changed to {dto.Role}");
        }

        [Authorize(Roles = AppRoles.Admin)]
        [HttpGet("v")]
        public ActionResult view()
        {

            return Ok("yes");

        }
    }
}
