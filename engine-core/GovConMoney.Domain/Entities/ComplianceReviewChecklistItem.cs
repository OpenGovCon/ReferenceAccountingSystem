using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class ComplianceReviewChecklistItem : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid InternalAuditCycleId { get; init; }
    public string ClauseRef { get; set; } = string.Empty;
    public string ControlName { get; set; } = string.Empty;
    public ComplianceChecklistResult? Result { get; set; }
    public string? Notes { get; set; }
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid UpdatedByUserId { get; set; }
}
