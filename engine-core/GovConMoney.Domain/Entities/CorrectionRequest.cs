namespace GovConMoney.Domain.Entities;

public class CorrectionRequest : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetId { get; init; }
    public Guid RequestedByUserId { get; init; }
    public string ReasonForChange { get; init; } = string.Empty;
    public bool Approved { get; set; }
    public DateTime RequestedAtUtc { get; init; } = DateTime.UtcNow;
}

