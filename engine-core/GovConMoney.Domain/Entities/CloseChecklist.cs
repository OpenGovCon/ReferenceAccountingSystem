namespace GovConMoney.Domain.Entities;

public class CloseChecklist : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid AccountingPeriodId { get; init; }
    public DateTime CompletedAtUtc { get; init; } = DateTime.UtcNow;
    public Guid CompletedByUserId { get; init; }
    public string StepsJson { get; init; } = "[]";
    public string? Notes { get; init; }
}
