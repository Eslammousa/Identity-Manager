using Microsoft.AspNetCore.Identity;

namespace Identity.Core.Domain.IdentityEntities
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string? PersonName { get; set; }

        public string UserType { get; set; } = "User";

        public string? RefreshToken { get; set; } // to store refresh token

        public DateTime? RefreshTokenExpirationDateTime { get; set; }
    }
}
