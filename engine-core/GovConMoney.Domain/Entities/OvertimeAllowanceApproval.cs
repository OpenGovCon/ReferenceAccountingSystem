namespace GovConMoney.Domain.Entities;

public class OvertimeAllowanceApproval : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid UserId { get; init; }
    public DateOnly WorkDate { get; init; }
    public int ApprovedOvertimeMinutes { get; init; }
    public Guid ApprovedByUserId { get; init; }
    public string Reason { get; init; } = string.Empty;
    public DateTime ApprovedAtUtc { get; init; } = DateTime.UtcNow;
}
