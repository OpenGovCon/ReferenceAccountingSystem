using GovConMoney.Application.Abstractions;
using GovConMoney.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace GovConMoney.Infrastructure.Persistence;

public sealed class InMemoryRepository(GovConMoneyDbContext db) : IRepository
{
    public IQueryable<T> Query<T>(Guid tenantId) where T : class, ITenantScoped
    {
        return db.Set<T>().Where(x => x.TenantId == tenantId);
    }

    public void Add<T>(T entity) where T : class
    {
        db.Set<T>().Add(entity);
        db.SaveChanges();
    }

    public void Update<T>(T entity) where T : class
    {
        db.Set<T>().Update(entity);
        db.SaveChanges();
    }

}
