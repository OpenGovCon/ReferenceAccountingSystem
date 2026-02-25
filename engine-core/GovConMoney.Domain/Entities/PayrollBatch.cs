namespace GovConMoney.Domain.Entities;

public class PayrollBatch : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string ExternalBatchId { get; init; } = string.Empty;
    public string SourceSystem { get; init; } = string.Empty;
    public DateOnly PeriodStart { get; init; }
    public DateOnly PeriodEnd { get; init; }
    public DateTime ImportedAtUtc { get; init; } = DateTime.UtcNow;
    public Guid ImportedByUserId { get; init; }
    public string? SourceChecksum { get; init; }
    public string? Notes { get; init; }
}
