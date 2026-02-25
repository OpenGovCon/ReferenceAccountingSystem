using GovConMoney.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace GovConMoney.Web.Security;

public static class IdentitySeed
{
    public const string SeedPassword = "TempPass#2026!";

    public static async Task InitializeAsync(IServiceProvider services)
    {
        var store = services.GetRequiredService<InMemoryDataStore>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = services.GetRequiredService<UserManager<GovConIdentityUser>>();

        var roles = new[] { "Admin", "Compliance", "TimeReporter", "Supervisor", "Accountant", "Manager" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                var roleResult = await roleManager.CreateAsync(new IdentityRole(role));
                if (!roleResult.Succeeded)
                {
                    throw new InvalidOperationException($"Unable to seed role {role}: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                }
            }
        }

        foreach (var appUser in store.Users)
        {
            var existing = await userManager.FindByIdAsync(appUser.Id.ToString());
            if (existing is not null)
            {
                await SyncClaimsAsync(userManager, existing);
                continue;
            }

            var identityUser = new GovConIdentityUser
            {
                Id = appUser.Id.ToString(),
                DomainUserId = appUser.Id,
                TenantId = appUser.TenantId,
                UserName = appUser.UserName,
                Email = appUser.Email,
                EmailConfirmed = true,
                LockoutEnabled = true,
                PasskeyRequired = appUser.PasskeyRequired
            };

            var createResult = await userManager.CreateAsync(identityUser, SeedPassword);
            if (!createResult.Succeeded)
            {
                throw new InvalidOperationException($"Unable to seed identity user {appUser.UserName}: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
            }

            foreach (var role in appUser.Roles.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var addRoleResult = await userManager.AddToRoleAsync(identityUser, role);
                if (!addRoleResult.Succeeded)
                {
                    throw new InvalidOperationException($"Unable to add role {role} to {appUser.UserName}: {string.Join(", ", addRoleResult.Errors.Select(e => e.Description))}");
                }
            }

            if (appUser.IsDisabled)
            {
                await userManager.SetLockoutEndDateAsync(identityUser, DateTimeOffset.MaxValue);
            }

            await userManager.SetTwoFactorEnabledAsync(identityUser, appUser.MfaEnabled);
            await SyncClaimsAsync(userManager, identityUser);
        }
    }

    private static async Task SyncClaimsAsync(UserManager<GovConIdentityUser> userManager, GovConIdentityUser user)
    {
        var claims = await userManager.GetClaimsAsync(user);

        await ReplaceClaimAsync(userManager, user, claims, "tenant_id", user.TenantId.ToString());
        await ReplaceClaimAsync(userManager, user, claims, "domain_user_id", user.DomainUserId.ToString());
        await ReplaceClaimAsync(userManager, user, claims, "passkey_required", user.PasskeyRequired.ToString().ToLowerInvariant());
    }

    private static async Task ReplaceClaimAsync(
        UserManager<GovConIdentityUser> userManager,
        GovConIdentityUser user,
        IEnumerable<Claim> claims,
        string claimType,
        string value)
    {
        foreach (var existing in claims.Where(c => c.Type == claimType).ToList())
        {
            await userManager.RemoveClaimAsync(user, existing);
        }

        await userManager.AddClaimAsync(user, new Claim(claimType, value));
    }
}
