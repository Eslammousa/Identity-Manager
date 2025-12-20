using Identity.Core.Domain.IdentityEntities;
using Identity.Core.DTO;
using System.Security.Claims;

namespace Identity.Core.ServiceContracts
{
    public interface IjwtService
    {
        AuthenticationResponse CreateJwtToken(ApplicationUser user);
        ClaimsPrincipal? GetPrincipalFromJwtToken(string? token);
    }
}
