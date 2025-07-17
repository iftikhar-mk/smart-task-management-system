using Microsoft.AspNetCore.Identity;
using Shared.Enums;

namespace AuthService.Seeding
{
    public static class RoleSeeder
    {
        public static async Task SeedAsync(IServiceProvider services)
        {
            try
            {
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

                var predefinedRoles = Enum.GetNames(typeof(AppRole));

                foreach (var role in predefinedRoles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        await roleManager.CreateAsync(new IdentityRole(role));
                    }
                }
            }
            catch (Exception)
            {
            }
        }
    }
}