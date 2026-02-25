namespace GovConMoney.Domain.Entities;

public class PasskeyCredential : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid UserId { get; init; }
    public string CredentialId { get; init; } = string.Empty;
    public string PublicKey { get; init; } = string.Empty;
    public uint SignCount { get; set; }
    public string UserHandle { get; set; } = string.Empty;
    public string Transports { get; set; } = string.Empty;
    public string Aaguid { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
}

