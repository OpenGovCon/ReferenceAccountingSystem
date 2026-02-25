namespace GovConMoney.Domain.Entities;

public class TimesheetApproval : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetId { get; init; }
    public Guid ApproverUserId { get; init; }
    public DateTime ApprovedAtUtc { get; init; } = DateTime.UtcNow;
}

