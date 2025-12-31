using Identity.Core.Domain.IdentityEntities;
using Identity.Core.DTO;
using System.Security.Claims;

namespace Identity.Core.ServiceContracts
{
    public interface IjwtService
    {
        Task <AuthenticationResponse> CreateJwtToken(ApplicationUser user);
        Task<ClaimsPrincipal?> GetPrincipalFromJwtToken(string? token);
    }
}
