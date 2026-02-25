using System.Data;
using System.Data.Common;
using GovConMoney.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace GovConMoney.Web.Services;

internal static class DbMigrationBootstrapper
{
    public static void ApplyMigrationsWithLegacyBaseline(GovConMoneyDbContext db)
    {
        if (NeedsLegacyBaseline(db))
        {
            BaselineInitialMigration(db);
        }

        db.Database.Migrate();
    }

    private static bool NeedsLegacyBaseline(GovConMoneyDbContext db)
    {
        // Existing legacy databases already have core domain tables.
        var hasAccountingPeriods = SqlObjectExists(db, "U", "AccountingPeriods");
        if (!hasAccountingPeriods)
        {
            return false;
        }

        var initialMigrationId = GetInitialMigrationId(db);
        if (string.IsNullOrWhiteSpace(initialMigrationId))
        {
            return false;
        }

        var historyExists = SqlObjectExists(db, "U", "__EFMigrationsHistory");
        if (!historyExists)
        {
            return true;
        }

        return !HistoryContainsMigration(db, initialMigrationId);
    }

    private static bool SqlObjectExists(GovConMoneyDbContext db, string objectType, string objectName)
    {
        const string sql = """
            SELECT CASE WHEN OBJECT_ID(@fullName, @objectType) IS NULL THEN 0 ELSE 1 END;
            """;

        var result = ExecuteScalarInt(db, sql, ("@fullName", $"[dbo].[{objectName}]"), ("@objectType", objectType));
        return result == 1;
    }

    private static int ExecuteScalarInt(GovConMoneyDbContext db, string sql, params (string Name, object Value)[] parameters)
    {
        using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = sql;
        command.CommandType = CommandType.Text;

        foreach (var (name, value) in parameters)
        {
            var parameter = command.CreateParameter();
            parameter.ParameterName = name;
            parameter.Value = value;
            command.Parameters.Add(parameter);
        }

        var connection = command.Connection!;
        var openedHere = connection.State != ConnectionState.Open;
        if (openedHere)
        {
            connection.Open();
        }

        try
        {
            var raw = command.ExecuteScalar();
            return raw is null or DBNull ? 0 : Convert.ToInt32(raw);
        }
        finally
        {
            if (openedHere)
            {
                connection.Close();
            }
        }
    }

    private static void BaselineInitialMigration(GovConMoneyDbContext db)
    {
        db.Database.ExecuteSqlRaw("""
            IF OBJECT_ID(N'[dbo].[__EFMigrationsHistory]', N'U') IS NULL
            BEGIN
                CREATE TABLE [dbo].[__EFMigrationsHistory](
                    [MigrationId] nvarchar(150) NOT NULL,
                    [ProductVersion] nvarchar(32) NOT NULL,
                    CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
                );
            END
            """);

        var initialMigrationId = GetInitialMigrationId(db);
        if (string.IsNullOrWhiteSpace(initialMigrationId))
        {
            return;
        }

        var productVersion = typeof(DbContext).Assembly.GetName().Version?.ToString(3) ?? "10.0.1";
        db.Database.ExecuteSqlRaw("""
            IF NOT EXISTS (SELECT 1 FROM [dbo].[__EFMigrationsHistory] WHERE [MigrationId] = {0})
            BEGIN
                INSERT INTO [dbo].[__EFMigrationsHistory] ([MigrationId], [ProductVersion])
                VALUES ({0}, {1});
            END
            """, initialMigrationId, productVersion);
    }

    private static string? GetInitialMigrationId(GovConMoneyDbContext db)
    {
        var migrationsAssembly = db.GetService<IMigrationsAssembly>();
        return migrationsAssembly.Migrations.Keys.OrderBy(x => x).FirstOrDefault();
    }

    private static bool HistoryContainsMigration(GovConMoneyDbContext db, string migrationId)
    {
        const string sql = """
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM [dbo].[__EFMigrationsHistory] WHERE [MigrationId] = @migrationId
            ) THEN 1 ELSE 0 END;
            """;

        return ExecuteScalarInt(db, sql, ("@migrationId", migrationId)) == 1;
    }
}
