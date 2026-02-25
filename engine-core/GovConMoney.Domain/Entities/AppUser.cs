namespace GovConMoney.Domain.Entities;

public class AppUser : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string EmployeeExternalId { get; set; } = string.Empty;
    public bool IsDisabled { get; set; }
    public bool MfaEnabled { get; set; }
    public bool PasskeyRequired { get; set; }
    public List<string> Roles { get; } = new();
}

