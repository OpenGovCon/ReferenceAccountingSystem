namespace GovConMoney.Domain.Entities;

public class BillingCeiling : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid ContractId { get; set; }
    public decimal FundedAmount { get; set; }
    public decimal CeilingAmount { get; set; }
    public DateOnly EffectiveStartDate { get; set; }
    public DateOnly EffectiveEndDate { get; set; }
    public bool IsActive { get; set; } = true;
}
