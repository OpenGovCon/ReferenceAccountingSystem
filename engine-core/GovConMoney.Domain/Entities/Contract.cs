using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class Contract : ITenantScoped, ISoftDeletable
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string ContractNumber { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public decimal BudgetAmount { get; set; }
    public ContractType ContractType { get; set; }
    public bool RequiresClinTracking { get; set; }
    public DateOnly BaseYearStartDate { get; set; }
    public DateOnly BaseYearEndDate { get; set; }
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAtUtc { get; set; }
    public Guid? DeletedByUserId { get; set; }
}

