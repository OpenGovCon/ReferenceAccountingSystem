using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class InternalAuditCycle : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid AccountingPeriodId { get; init; }
    public InternalAuditReviewType ReviewType { get; set; } = InternalAuditReviewType.InternalAudit;
    public DateOnly PeriodStart { get; set; }
    public DateOnly PeriodEnd { get; set; }
    public DateOnly DueDate { get; set; }
    public InternalAuditCycleStatus Status { get; set; } = InternalAuditCycleStatus.Draft;
    public bool TieOutReviewCompleted { get; set; }
    public bool UnallowableReviewCompleted { get; set; }
    public bool BillingReviewCompleted { get; set; }
    public bool MonthlyCloseReviewCompleted { get; set; }
    public Guid CreatedByUserId { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? SubmittedAtUtc { get; set; }
    public Guid? SubmittedByUserId { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public Guid? CompletedByUserId { get; set; }
    public DateTime? ClosedAtUtc { get; set; }
    public Guid? ClosedByUserId { get; set; }
    public string? Summary { get; set; }
    public string? Notes { get; set; }
}
