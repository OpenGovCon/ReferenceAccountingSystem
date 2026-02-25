namespace GovConMoney.Domain.Entities;

public class CorrectionApproval : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid CorrectionRequestId { get; init; }
    public Guid ApproverUserId { get; init; }
    public DateTime ApprovedAtUtc { get; init; } = DateTime.UtcNow;
}

