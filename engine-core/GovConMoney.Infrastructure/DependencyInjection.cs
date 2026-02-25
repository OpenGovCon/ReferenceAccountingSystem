using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Services;
using GovConMoney.Infrastructure.Persistence;
using GovConMoney.Infrastructure.Security;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;

namespace GovConMoney.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddGovConMoney(this IServiceCollection services)
    {
        services.AddScoped<InMemoryDataStore>();
        services.AddHttpContextAccessor();
        services.AddScoped<TenantContextAccessor>(sp =>
        {
            var context = new TenantContextAccessor();
            var httpContext = sp.GetRequiredService<Microsoft.AspNetCore.Http.IHttpContextAccessor>().HttpContext;
            var principal = httpContext?.User;
            if (principal?.Identity?.IsAuthenticated != true)
            {
                return context;
            }

            if (Guid.TryParse(principal.FindFirst("tenant_id")?.Value, out var tenantId))
            {
                context.TenantId = tenantId;
            }

            if (Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            {
                context.UserId = userId;
            }

            context.Roles = principal.FindAll(ClaimTypes.Role).Select(x => x.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            return context;
        });
        services.AddScoped<ITenantContext>(sp => sp.GetRequiredService<TenantContextAccessor>());
        services.AddScoped<IRepository, InMemoryRepository>();
        services.AddScoped<IAuditService, InMemoryAuditService>();
        services.AddScoped<IClock, SystemClock>();
        services.AddScoped<ICorrelationContext, CorrelationContext>();
        services.AddScoped<IAppTransaction, InMemoryTransaction>();

        services.AddScoped<ComplianceService>();
        services.AddScoped<TimecardValidationEngine>();
        services.AddScoped<NotificationService>();
        services.AddScoped<TimesheetService>();
        services.AddScoped<AccountingService>();
        services.AddScoped<JournalEntryWorkflowService>();
        services.AddScoped<IndirectRateService>();
        services.AddScoped<CloseService>();
        services.AddScoped<MonthlyCloseComplianceService>();
        services.AddScoped<InternalAuditService>();
        services.AddScoped<PayrollService>();
        services.AddScoped<BillingService>();
        services.AddScoped<ReportingService>();
        services.AddScoped<PasskeyService>();

        return services;
    }
}
