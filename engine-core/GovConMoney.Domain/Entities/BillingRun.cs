using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class BillingRun : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public DateOnly PeriodStart { get; set; }
    public DateOnly PeriodEnd { get; set; }
    public DateTime RunDateUtc { get; set; } = DateTime.UtcNow;
    public BillingRunStatus Status { get; set; } = BillingRunStatus.Draft;
    public Guid CreatedByUserId { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public Guid? PostedByUserId { get; set; }
    public DateTime? PostedAtUtc { get; set; }
    public string? Notes { get; set; }
}
