using GovConMoney.Application.Models;
using Microsoft.Extensions.Caching.Memory;

namespace GovConMoney.Web.Services;

public sealed class PayrollImportPreviewStore(IMemoryCache cache)
{
    public Guid Save(PayrollImportPreview preview)
    {
        var token = Guid.NewGuid();
        cache.Set(token, preview, TimeSpan.FromMinutes(30));
        return token;
    }

    public PayrollImportPreview? Get(Guid token)
        => cache.TryGetValue(token, out PayrollImportPreview? preview) ? preview : null;

    public void Remove(Guid token)
        => cache.Remove(token);
}

public sealed record PayrollImportPreview(
    string ExternalBatchId,
    string SourceSystem,
    DateOnly PeriodStart,
    DateOnly PeriodEnd,
    string? SourceChecksum,
    string? Notes,
    IReadOnlyList<PayrollImportLineRequest> Lines,
    IReadOnlyList<PayrollImportValidationRow> ValidationRows,
    IReadOnlyList<PayrollImportValidationSummary> ValidationSummary,
    bool HasBlockingErrors);

public sealed record PayrollImportValidationRow(
    int LineNumber,
    string EmployeeExternalId,
    string? MatchedUserName,
    decimal LaborAmount,
    decimal FringeAmount,
    decimal TaxAmount,
    decimal OtherAmount,
    string Severity,
    string Message);

public sealed record PayrollImportValidationSummary(
    string Severity,
    string Message,
    int Count);
