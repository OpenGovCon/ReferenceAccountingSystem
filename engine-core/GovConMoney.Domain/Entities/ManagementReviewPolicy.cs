namespace GovConMoney.Domain.Entities;

public class ManagementReviewPolicy : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public bool RequireManagerApprovalForBillingAboveThreshold { get; set; } = true;
    public decimal BillingManagerApprovalThreshold { get; set; } = 50000m;
    public bool RequireManagerCoSignForAdjustingAboveThreshold { get; set; } = true;
    public decimal AdjustingManagerCoSignThreshold { get; set; } = 10000m;
    public bool EnablePeriodicInternalAuditAttestation { get; set; } = true;
    public int InternalAuditCadenceDays { get; set; } = 30;
    public int InternalAuditDueDaysAfterPeriodEnd { get; set; } = 10;
    public bool RequireManagerInternalAuditAttestation { get; set; } = true;
    public bool RequireComplianceInternalAuditAttestation { get; set; } = true;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid? UpdatedByUserId { get; set; }
}
