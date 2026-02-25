using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class ContractPricing : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid ContractId { get; init; }
    public string LaborCategory { get; set; } = string.Empty;
    public LaborSite Site { get; set; }
    public decimal BaseHourlyRate { get; set; }
    public decimal EscalationPercent { get; set; }
    public decimal FeePercent { get; set; }
    public DateOnly EffectiveStartDate { get; set; }
    public DateOnly EffectiveEndDate { get; set; }
}

