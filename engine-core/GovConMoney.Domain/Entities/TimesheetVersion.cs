namespace GovConMoney.Domain.Entities;

public class TimesheetVersion : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetId { get; init; }
    public int VersionNumber { get; init; }
    public string SnapshotJson { get; init; } = string.Empty;
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
}

