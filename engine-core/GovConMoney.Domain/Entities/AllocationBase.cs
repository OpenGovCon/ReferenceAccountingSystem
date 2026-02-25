using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class AllocationBase : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid IndirectPoolId { get; init; }
    public string Name { get; set; } = string.Empty;
    public CostType BaseCostType { get; set; } = CostType.Direct;
    public AllocationBaseMethod BaseMethod { get; set; } = AllocationBaseMethod.PoolBaseCostTypeLaborDollars;
    public bool IsActive { get; set; } = true;
}

