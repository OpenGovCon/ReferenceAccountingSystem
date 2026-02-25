using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class AllowabilityRule : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public CostType CostType { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public string RuleDescription { get; set; } = string.Empty;
    public bool RequiresComment { get; set; }
}

