using Identity.Core.Domain.IdentityEntities;
using Identity.Core.DTO;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Core.Services
{
    public static class IdentitySeeder
    {
        public static async Task SeedAsync(
    RoleManager<ApplicationRole> roleManager,
    UserManager<ApplicationUser> userManager)
        {
            // ===== Create Roles =====
            string[] roles = { AppRoles.Admin,  AppRoles.User };

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new ApplicationRole
                    {
                        Name = role
                    });
                }
            }

            // ===== Create Admin =====
            var adminEmail = "admin@example.com";
            var admin = await userManager.FindByEmailAsync(adminEmail);

            if (admin == null)
            {
                admin = new ApplicationUser
                {
                    Email = adminEmail,
                    UserName = adminEmail,
                    PersonName = "Eslam Mousa",
                     UserType = AppRoles.Admin

                };

                var createResult = await userManager.CreateAsync(admin, "admin123");
                if (createResult.Succeeded)
                {
                    await userManager.AddToRoleAsync(admin, AppRoles.Admin);
                }
                else
                {
                    // optional: log errors
                    var errors = string.Join(" | ",
                        createResult.Errors.Select(e => e.Description));
                    throw new Exception(errors);
                }
            }
        }
    }
}
