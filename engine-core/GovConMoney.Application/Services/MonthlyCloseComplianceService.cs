using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;

namespace GovConMoney.Application.Services;

public sealed class MonthlyCloseComplianceService(
    IRepository repository,
    ITenantContext tenantContext,
    IClock clock)
{
    public IReadOnlyList<MonthlyCloseComplianceRow> CloseCadenceStatus(DateOnly? asOfDate = null, int closeGraceDays = 10)
    {
        var asOf = asOfDate ?? DateOnly.FromDateTime(clock.UtcNow.Date);
        var graceDays = Math.Max(0, closeGraceDays);

        var periods = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .OrderByDescending(x => x.EndDate)
            .ToList();
        if (periods.Count == 0)
        {
            return [];
        }

        return periods.Select(period =>
        {
            var closeDeadline = period.EndDate.AddDays(graceDays);
            var daysPastEnd = asOf > period.EndDate ? asOf.DayNumber - period.EndDate.DayNumber : 0;
            var daysPastDeadline = asOf > closeDeadline ? asOf.DayNumber - closeDeadline.DayNumber : 0;
            var journalEntryCount = repository.Query<JournalEntry>(tenantContext.TenantId)
                .Count(x => x.EntryDate >= period.StartDate && x.EntryDate <= period.EndDate);
            var isOverdue = period.Status == AccountingPeriodStatus.Open && asOf > closeDeadline;

            return new MonthlyCloseComplianceRow(
                period.Id,
                period.StartDate,
                period.EndDate,
                period.Status.ToString(),
                closeDeadline,
                daysPastEnd,
                daysPastDeadline,
                journalEntryCount,
                isOverdue);
        }).ToList();
    }
}
