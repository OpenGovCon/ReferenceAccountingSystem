using GovConMoney.Application.Abstractions;
using GovConMoney.Domain.Entities;
using GovConMoney.Infrastructure.Persistence;

namespace GovConMoney.Infrastructure.Security;

public sealed class SystemClock : IClock
{
    public DateTime UtcNow => DateTime.UtcNow;
}

public sealed class CorrelationContext : ICorrelationContext
{
    public string CorrelationId => Guid.NewGuid().ToString("N");
}

public sealed class InMemoryTransaction : IAppTransaction
{
    public InMemoryTransaction(InMemoryDataStore store)
    {
        _store = store;
    }

    private readonly InMemoryDataStore _store;

    public void Execute(Action action)
    {
        try
        {
            using var dbTx = _store.Database.BeginTransaction();
            action();
            dbTx.Commit();
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Transactions are not supported by the in-memory store", StringComparison.OrdinalIgnoreCase))
        {
            action();
        }
    }
}

public sealed class InMemoryAuditService(InMemoryDataStore store, Microsoft.AspNetCore.Http.IHttpContextAccessor httpContextAccessor) : IAuditService
{
    public void Record(AuditEvent auditEvent)
    {
        var httpContext = httpContextAccessor.HttpContext;
        auditEvent.IpAddress ??= httpContext?.Connection.RemoteIpAddress?.ToString();
        auditEvent.UserAgent ??= httpContext?.Request.Headers.UserAgent.ToString();
        store.AuditEvents.Add(auditEvent);
        store.SaveChanges();
    }
}

public sealed class TenantContextAccessor : ITenantContext
{
    public Guid TenantId { get; set; }
    public Guid UserId { get; set; }
    public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
}
