namespace GovConMoney.Domain.Entities;

public interface ISoftDeletable
{
    bool IsDeleted { get; }
    DateTime? DeletedAtUtc { get; }
    Guid? DeletedByUserId { get; }
}
