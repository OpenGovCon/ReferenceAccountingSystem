namespace GovConMoney.Domain.Entities;

public class Clin : ITenantScoped, ISoftDeletable
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TaskOrderId { get; init; }
    public string Number { get; set; } = string.Empty;
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAtUtc { get; set; }
    public Guid? DeletedByUserId { get; set; }
}

