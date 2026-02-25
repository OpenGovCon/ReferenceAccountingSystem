using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class ComplianceException : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid InternalAuditCycleId { get; init; }
    public Guid? ChecklistItemId { get; set; }
    public ComplianceExceptionSeverity Severity { get; set; }
    public ComplianceExceptionCategory Category { get; set; }
    public string Description { get; set; } = string.Empty;
    public string? RootCause { get; set; }
    public string? RemediationPlan { get; set; }
    public Guid? OwnerUserId { get; set; }
    public DateOnly? DueDate { get; set; }
    public ComplianceExceptionStatus Status { get; set; } = ComplianceExceptionStatus.Open;
    public DateTime? ResolvedAtUtc { get; set; }
    public Guid? ResolvedByUserId { get; set; }
    public string? ResolutionNotes { get; set; }
}
