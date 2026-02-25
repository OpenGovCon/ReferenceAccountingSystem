using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using GovConMoney.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GovConMoney.Web.Services;

public sealed class MonthlyCloseComplianceHostedService(
    IServiceProvider serviceProvider,
    ILogger<MonthlyCloseComplianceHostedService> logger) : BackgroundService
{
    private const int DefaultCloseGraceDays = 10;
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        await RunCheckCycle(stoppingToken);

        using var timer = new PeriodicTimer(CheckInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await RunCheckCycle(stoppingToken);
        }
    }

    private async Task RunCheckCycle(CancellationToken cancellationToken)
    {
        try
        {
            using var scope = serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<GovConMoneyDbContext>();
            var utcNow = DateTime.UtcNow;
            var asOf = DateOnly.FromDateTime(utcNow.Date);

            var tenants = await db.Tenants
                .Select(x => new { x.Id, x.Name })
                .ToListAsync(cancellationToken);

            foreach (var tenant in tenants)
            {
                var periods = await db.AccountingPeriods
                    .Where(x => x.TenantId == tenant.Id && x.Status == AccountingPeriodStatus.Open)
                    .OrderBy(x => x.EndDate)
                    .ToListAsync(cancellationToken);
                if (periods.Count == 0)
                {
                    continue;
                }

                var overdue = periods
                    .Select(x =>
                    {
                        var closeDeadline = x.EndDate.AddDays(DefaultCloseGraceDays);
                        var daysPastDeadline = asOf > closeDeadline ? asOf.DayNumber - closeDeadline.DayNumber : 0;
                        return new
                        {
                            Period = x,
                            CloseDeadline = closeDeadline,
                            DaysPastDeadline = daysPastDeadline,
                            IsOverdue = asOf > closeDeadline
                        };
                    })
                    .Where(x => x.IsOverdue)
                    .ToList();
                if (overdue.Count == 0)
                {
                    continue;
                }

                var alreadyNotified = await db.UserNotifications.AnyAsync(
                    x => x.TenantId == tenant.Id
                      && x.Category == "MonthlyCloseCompliance"
                      && x.CreatedAtUtc.Date == utcNow.Date,
                    cancellationToken);
                if (!alreadyNotified)
                {
                    var oldest = overdue.OrderByDescending(x => x.DaysPastDeadline).First();
                    var title = $"Monthly close overdue ({overdue.Count} open period(s))";
                    var message =
                        $"Tenant '{tenant.Name}' has {overdue.Count} overdue open accounting period(s). " +
                        $"Oldest period {oldest.Period.StartDate:yyyy-MM-dd} to {oldest.Period.EndDate:yyyy-MM-dd} " +
                        $"is {oldest.DaysPastDeadline} day(s) past close deadline ({oldest.CloseDeadline:yyyy-MM-dd}).";

                    db.UserNotifications.Add(new UserNotification
                    {
                        TenantId = tenant.Id,
                        Title = title,
                        Message = message,
                        Category = "MonthlyCloseCompliance",
                        TargetRole = "Accountant",
                        CreatedAtUtc = utcNow
                    });
                    db.UserNotifications.Add(new UserNotification
                    {
                        TenantId = tenant.Id,
                        Title = title,
                        Message = message,
                        Category = "MonthlyCloseCompliance",
                        TargetRole = "Manager",
                        CreatedAtUtc = utcNow
                    });
                }

                var maxDaysPastDeadline = overdue.Max(x => x.DaysPastDeadline);
                if (maxDaysPastDeadline < 30)
                {
                    continue;
                }

                var escalationSent = await db.UserNotifications.AnyAsync(
                    x => x.TenantId == tenant.Id
                      && x.Category == "MonthlyCloseEscalation"
                      && x.CreatedAtUtc.Date == utcNow.Date,
                    cancellationToken);
                if (escalationSent)
                {
                    continue;
                }

                var escalationTitle = "Monthly close escalation required";
                var escalationMessage =
                    $"Tenant '{tenant.Name}' has open periods at least 30 day(s) past close deadline. " +
                    "Management escalation is required.";

                db.UserNotifications.Add(new UserNotification
                {
                    TenantId = tenant.Id,
                    Title = escalationTitle,
                    Message = escalationMessage,
                    Category = "MonthlyCloseEscalation",
                    TargetRole = "Manager",
                    CreatedAtUtc = utcNow
                });
                db.UserNotifications.Add(new UserNotification
                {
                    TenantId = tenant.Id,
                    Title = escalationTitle,
                    Message = escalationMessage,
                    Category = "MonthlyCloseEscalation",
                    TargetRole = "Admin",
                    CreatedAtUtc = utcNow
                });
            }

            await db.SaveChangesAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Monthly close compliance background check failed.");
        }
    }
}
