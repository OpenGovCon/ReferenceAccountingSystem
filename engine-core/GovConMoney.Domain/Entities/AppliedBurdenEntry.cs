namespace GovConMoney.Domain.Entities;

public class AppliedBurdenEntry : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetLineId { get; init; }
    public Guid IndirectPoolId { get; init; }
    public Guid RateCalculationId { get; init; }
    public DateOnly PeriodStart { get; init; }
    public DateOnly PeriodEnd { get; init; }
    public Guid ContractId { get; init; }
    public Guid TaskOrderId { get; init; }
    public Guid ClinId { get; init; }
    public Guid WbsNodeId { get; init; }
    public Guid ChargeCodeId { get; init; }
    public decimal BaseAmount { get; init; }
    public decimal BurdenAmount { get; init; }
    public bool IsAdjustment { get; init; }
    public DateTime AppliedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? PostedAtUtc { get; set; }
    public Guid? PostedJournalEntryId { get; set; }
}

