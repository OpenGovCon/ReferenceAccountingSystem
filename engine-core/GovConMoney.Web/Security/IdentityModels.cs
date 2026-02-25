using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace GovConMoney.Web.Security;

public sealed class GovConIdentityUser : IdentityUser
{
    public Guid TenantId { get; set; }
    public Guid DomainUserId { get; set; }
    public bool PasskeyRequired { get; set; }
}

public sealed class GovConIdentityDbContext(DbContextOptions<GovConIdentityDbContext> options)
    : IdentityDbContext<GovConIdentityUser, IdentityRole, string>(options)
{
}
