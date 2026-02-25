namespace GovConMoney.Domain.Entities;

public class Assignment : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid UserId { get; init; }
    public Guid ChargeCodeId { get; init; }
    public DateOnly EffectiveStartDate { get; init; }
    public DateOnly EffectiveEndDate { get; init; }
    public bool SupervisorOverrideAllowed { get; set; }
}

