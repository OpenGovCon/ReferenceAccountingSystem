using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class Timesheet : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid UserId { get; init; }
    public DateOnly PeriodStart { get; init; }
    public DateOnly PeriodEnd { get; init; }
    public TimesheetStatus Status { get; set; } = TimesheetStatus.Draft;
    public string? Attestation { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? SubmittedAtUtc { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public int VersionNumber { get; set; } = 1;
    public bool IsComplianceFlagged { get; set; }
    public string? ComplianceIssuesJson { get; set; }
    public DateTime? LastComplianceCheckedAtUtc { get; set; }
    public DateTime? PostedAtUtc { get; set; }
    public Guid? PostedJournalEntryId { get; set; }
}

