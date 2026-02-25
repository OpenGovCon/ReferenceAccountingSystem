namespace GovConMoney.Domain.Entities;

public class TaskOrder : ITenantScoped, ISoftDeletable
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid ContractId { get; init; }
    public string Number { get; set; } = string.Empty;
    public decimal BudgetAmount { get; set; }
    public bool RequiresClinTracking { get; set; }
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAtUtc { get; set; }
    public Guid? DeletedByUserId { get; set; }
}

