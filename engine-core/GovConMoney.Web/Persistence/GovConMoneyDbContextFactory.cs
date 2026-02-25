using GovConMoney.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace GovConMoney.Web.Persistence;

public sealed class GovConMoneyDbContextFactory : IDesignTimeDbContextFactory<GovConMoneyDbContext>
{
    public GovConMoneyDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<GovConMoneyDbContext>();
        var connectionString =
            Environment.GetEnvironmentVariable("GOVCONMONEY_PRIMARY_CONNECTION")
            ?? "Server=.\\SQLEXPRESS;Database=GovConMoney;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True;";

        optionsBuilder.UseSqlServer(connectionString, sql =>
            sql.MigrationsAssembly("GovConMoney.Web"));
        return new GovConMoneyDbContext(optionsBuilder.Options);
    }
}
