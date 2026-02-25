namespace GovConMoney.Domain.Entities;

public class WorkPeriodConfiguration : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public int WeekStartDay { get; set; } = (int)DayOfWeek.Monday;
    public int PeriodLengthDays { get; set; } = 7;
    public bool DailyEntryRequired { get; set; } = true;
    public int DailyEntryGraceDays { get; set; } = 1;
    public bool DailyEntryHardFail { get; set; } = true;
    public bool DailyEntryIncludeWeekends { get; set; }
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
