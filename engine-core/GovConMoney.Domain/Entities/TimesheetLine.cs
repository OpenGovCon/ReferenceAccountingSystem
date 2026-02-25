using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class TimesheetLine : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetId { get; init; }
    public DateOnly WorkDate { get; set; }
    public Guid ChargeCodeId { get; set; }
    public int Minutes { get; set; }
    public CostType CostType { get; set; }
    public TimesheetEntryType EntryType { get; set; } = TimesheetEntryType.Work;
    public string Comment { get; set; } = string.Empty;
}

