namespace GovConMoney.Domain.Entities;

public class WbsNode : ITenantScoped, ISoftDeletable
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid ClinId { get; init; }
    public Guid? ParentWbsNodeId { get; set; }
    public string Code { get; set; } = string.Empty;
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAtUtc { get; set; }
    public Guid? DeletedByUserId { get; set; }
}

