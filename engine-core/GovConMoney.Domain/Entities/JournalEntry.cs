using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class JournalEntry : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public DateOnly EntryDate { get; set; }
    public string Description { get; set; } = string.Empty;
    public JournalEntryType EntryType { get; set; } = JournalEntryType.Standard;
    public JournalEntryStatus Status { get; set; } = JournalEntryStatus.Posted;
    public bool IsReversal { get; set; }
    public Guid? ReversalOfJournalEntryId { get; set; }
    public Guid? RequestedByUserId { get; set; }
    public DateTime? SubmittedAtUtc { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public DateTime? PostedAtUtc { get; set; }
    public string? Reason { get; set; }
    public string? DraftLinesJson { get; set; }
    public string? AttachmentRefs { get; set; }
}

