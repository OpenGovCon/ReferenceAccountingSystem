using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class ChartOfAccount : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string AccountNumber { get; init; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public CostType CostType { get; set; }
}

