namespace GovConMoney.Domain.Entities;

public class TimesheetWorkNote : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetId { get; init; }
    public Guid CreatedByUserId { get; init; }
    public string Note { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
}
