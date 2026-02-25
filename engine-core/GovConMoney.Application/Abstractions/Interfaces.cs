using GovConMoney.Domain.Entities;

namespace GovConMoney.Application.Abstractions;

public interface IRepository
{
    IQueryable<T> Query<T>(Guid tenantId) where T : class, ITenantScoped;
    void Add<T>(T entity) where T : class;
    void Update<T>(T entity) where T : class;
}

public interface IAuditService
{
    void Record(AuditEvent auditEvent);
}

public interface ICorrelationContext
{
    string CorrelationId { get; }
}

public interface IClock
{
    DateTime UtcNow { get; }
}

public interface ITenantContext
{
    Guid TenantId { get; }
    Guid UserId { get; }
    IReadOnlyCollection<string> Roles { get; }
}

public interface IAppTransaction
{
    void Execute(Action action);
}
