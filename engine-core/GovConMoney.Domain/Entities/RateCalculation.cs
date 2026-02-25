using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class RateCalculation : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid IndirectPoolId { get; init; }
    public DateOnly PeriodStart { get; init; }
    public DateOnly PeriodEnd { get; init; }
    public decimal PoolCost { get; init; }
    public decimal AllocationBaseTotal { get; init; }
    public decimal Rate { get; init; }
    public int Version { get; init; } = 1;
    public bool IsFinal { get; init; }
    public DateTime CalculatedAtUtc { get; init; } = DateTime.UtcNow;
    public Guid CalculatedByUserId { get; init; }
    public RateCalculationReviewStatus ReviewStatus { get; set; } = RateCalculationReviewStatus.NotRequired;
    public Guid? SubmittedForReviewByUserId { get; set; }
    public DateTime? SubmittedForReviewAtUtc { get; set; }
    public Guid? ReviewedByUserId { get; set; }
    public DateTime? ReviewedAtUtc { get; set; }
    public string? ReviewNote { get; set; }
}

