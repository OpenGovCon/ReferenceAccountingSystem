using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class IndirectPool : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string Name { get; set; } = string.Empty;
    public DateOnly EffectiveStartDate { get; set; } = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddYears(-1));
    public DateOnly EffectiveEndDate { get; set; } = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddYears(1));
    public CostType PoolCostType { get; set; } = CostType.Indirect;
    public CostType BaseCostType { get; set; } = CostType.Direct;
    public bool ExcludeUnallowable { get; set; } = true;
    public bool IsActive { get; set; } = true;
}

