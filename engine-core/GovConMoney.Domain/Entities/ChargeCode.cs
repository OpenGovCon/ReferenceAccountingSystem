using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class ChargeCode : ITenantScoped, ISoftDeletable
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid WbsNodeId { get; init; }
    public string Code { get; set; } = string.Empty;
    public CostType CostType { get; set; }
    public bool IsActive { get; set; } = true;
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAtUtc { get; set; }
    public Guid? DeletedByUserId { get; set; }
}

