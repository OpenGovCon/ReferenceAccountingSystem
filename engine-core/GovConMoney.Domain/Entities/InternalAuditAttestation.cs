using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class InternalAuditAttestation : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid InternalAuditCycleId { get; init; }
    public InternalAuditAttestationType AttestationType { get; set; }
    public Guid AttestedByUserId { get; set; }
    public string AttestedByRoles { get; set; } = string.Empty;
    public DateTime AttestedAtUtc { get; set; } = DateTime.UtcNow;
    public string Statement { get; set; } = string.Empty;
    public string? Notes { get; set; }
}
