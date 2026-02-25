namespace GovConMoney.Domain.Entities;

public class TimesheetDay : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetId { get; init; }
    public DateOnly WorkDate { get; init; }
}

