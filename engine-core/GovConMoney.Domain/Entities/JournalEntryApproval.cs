namespace GovConMoney.Domain.Entities;

public class JournalEntryApproval : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid JournalEntryId { get; init; }
    public Guid RequestedByUserId { get; init; }
    public Guid ApprovedByUserId { get; init; }
    public DateTime ApprovedAtUtc { get; init; } = DateTime.UtcNow;
    public string Reason { get; init; } = string.Empty;
    public string? AttachmentRefs { get; init; }
}
