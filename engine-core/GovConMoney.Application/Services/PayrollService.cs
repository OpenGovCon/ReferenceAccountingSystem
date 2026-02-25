using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Globalization;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public sealed class PayrollService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction)
{
    public IReadOnlyList<PayrollImportProfile> GetImportProfiles(bool includeInactive = false)
    {
        var query = repository.Query<PayrollImportProfile>(tenantContext.TenantId);
        if (!includeInactive)
        {
            query = query.Where(x => x.IsActive);
        }

        return query
            .OrderBy(x => x.Name)
            .ToList();
    }

    public PayrollImportProfile UpsertImportProfile(PayrollImportProfileUpsertRequest request)
    {
        var name = request.Name?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new DomainRuleException("Import profile name is required.");
        }

        var sourceSystem = string.IsNullOrWhiteSpace(request.SourceSystem) ? "PayrollExtract" : request.SourceSystem.Trim();
        var delimiter = string.IsNullOrWhiteSpace(request.Delimiter) ? "," : request.Delimiter.Trim();
        if (delimiter.Length != 1)
        {
            throw new DomainRuleException("Delimiter must be a single character.");
        }

        ValidateColumnMapping(request.EmployeeExternalIdColumn, "employee external id");
        ValidateColumnMapping(request.LaborAmountColumn, "labor amount");
        ValidateColumnMapping(request.FringeAmountColumn, "fringe amount");
        ValidateColumnMapping(request.TaxAmountColumn, "tax amount");
        ValidateColumnMapping(request.OtherAmountColumn, "other amount");
        if (!string.IsNullOrWhiteSpace(request.NotesColumn))
        {
            ValidateColumnMapping(request.NotesColumn!, "notes");
        }

        var existingByName = repository.Query<PayrollImportProfile>(tenantContext.TenantId)
            .SingleOrDefault(x => x.Name == name);
        if (existingByName is not null && request.ProfileId.HasValue && existingByName.Id != request.ProfileId.Value)
        {
            throw new DomainRuleException("A different payroll import profile already uses this name.");
        }

        PayrollImportProfile profile;
        var isCreate = false;
        if (request.ProfileId.HasValue)
        {
            profile = repository.Query<PayrollImportProfile>(tenantContext.TenantId)
                .SingleOrDefault(x => x.Id == request.ProfileId.Value)
                ?? throw new DomainRuleException("Payroll import profile not found.");
        }
        else if (existingByName is not null)
        {
            profile = existingByName;
        }
        else
        {
            isCreate = true;
            profile = new PayrollImportProfile
            {
                TenantId = tenantContext.TenantId,
                UpdatedByUserId = tenantContext.UserId
            };
            repository.Add(profile);
        }

        var before = JsonSerializer.Serialize(profile);
        profile.Name = name;
        profile.SourceSystem = sourceSystem;
        profile.Delimiter = delimiter;
        profile.HasHeaderRow = request.HasHeaderRow;
        profile.EmployeeExternalIdColumn = request.EmployeeExternalIdColumn.Trim();
        profile.LaborAmountColumn = request.LaborAmountColumn.Trim();
        profile.FringeAmountColumn = request.FringeAmountColumn.Trim();
        profile.TaxAmountColumn = request.TaxAmountColumn.Trim();
        profile.OtherAmountColumn = request.OtherAmountColumn.Trim();
        profile.NotesColumn = string.IsNullOrWhiteSpace(request.NotesColumn) ? null : request.NotesColumn.Trim();
        profile.RequiredHeadersCsv = string.IsNullOrWhiteSpace(request.RequiredHeadersCsv) ? null : request.RequiredHeadersCsv.Trim();
        profile.RequireKnownEmployeeExternalId = request.RequireKnownEmployeeExternalId;
        profile.DisallowDuplicateEmployeeExternalIds = request.DisallowDuplicateEmployeeExternalIds;
        profile.RequirePositiveLaborAmount = request.RequirePositiveLaborAmount;
        profile.IsActive = request.IsActive;
        profile.UpdatedAtUtc = clock.UtcNow;
        profile.UpdatedByUserId = tenantContext.UserId;
        repository.Update(profile);

        audit.Record(new AuditEvent
        {
            TenantId = tenantContext.TenantId,
            EntityType = "PayrollImportProfile",
            EntityId = profile.Id,
            EventType = isCreate ? EventType.Create : EventType.UpdateDraft,
            ActorUserId = tenantContext.UserId,
            ActorRoles = string.Join(',', tenantContext.Roles),
            OccurredAtUtc = clock.UtcNow,
            ReasonForChange = isCreate ? $"Created payroll import profile {profile.Name}." : $"Updated payroll import profile {profile.Name}.",
            BeforeJson = isCreate ? null : before,
            AfterJson = JsonSerializer.Serialize(profile),
            CorrelationId = correlation.CorrelationId
        });

        return profile;
    }

    public PayrollBatch ImportBatch(PayrollImportBatchRequest request)
    {
        if (request.PeriodEnd < request.PeriodStart)
        {
            throw new DomainRuleException("Payroll period end must be on or after period start.");
        }

        if (string.IsNullOrWhiteSpace(request.ExternalBatchId))
        {
            throw new DomainRuleException("External batch id is required.");
        }

        if (request.Lines is null || request.Lines.Count == 0)
        {
            throw new DomainRuleException("At least one payroll line is required.");
        }

        var externalBatchId = request.ExternalBatchId.Trim();
        var sourceSystem = string.IsNullOrWhiteSpace(request.SourceSystem) ? "Manual" : request.SourceSystem.Trim();
        var exists = repository.Query<PayrollBatch>(tenantContext.TenantId)
            .Any(x => x.ExternalBatchId == externalBatchId);
        if (exists)
        {
            throw new DomainRuleException("Payroll batch already exists.");
        }

        var usersByExternalId = repository.Query<AppUser>(tenantContext.TenantId)
            .Where(x => !string.IsNullOrWhiteSpace(x.EmployeeExternalId))
            .ToList()
            .GroupBy(x => x.EmployeeExternalId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        var batch = new PayrollBatch
        {
            TenantId = tenantContext.TenantId,
            ExternalBatchId = externalBatchId,
            SourceSystem = sourceSystem,
            PeriodStart = request.PeriodStart,
            PeriodEnd = request.PeriodEnd,
            ImportedAtUtc = clock.UtcNow,
            ImportedByUserId = tenantContext.UserId,
            SourceChecksum = request.SourceChecksum?.Trim(),
            Notes = request.Notes?.Trim()
        };

        transaction.Execute(() =>
        {
            repository.Add(batch);
            foreach (var line in request.Lines)
            {
                var employeeExternalId = line.EmployeeExternalId?.Trim() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(employeeExternalId))
                {
                    throw new DomainRuleException("Payroll line employee external id is required.");
                }

                if (line.LaborAmount < 0m || line.FringeAmount < 0m || line.TaxAmount < 0m || line.OtherAmount < 0m)
                {
                    throw new DomainRuleException("Payroll line amounts cannot be negative.");
                }

                var userId = usersByExternalId.TryGetValue(employeeExternalId, out var matchedUser)
                    ? matchedUser.Id
                    : (Guid?)null;

                repository.Add(new PayrollLine
                {
                    TenantId = tenantContext.TenantId,
                    PayrollBatchId = batch.Id,
                    EmployeeExternalId = employeeExternalId,
                    UserId = userId,
                    LaborAmount = Math.Round(line.LaborAmount, 2),
                    FringeAmount = Math.Round(line.FringeAmount, 2),
                    TaxAmount = Math.Round(line.TaxAmount, 2),
                    OtherAmount = Math.Round(line.OtherAmount, 2),
                    Notes = line.Notes?.Trim()
                });
            }

            audit.Record(new AuditEvent
            {
                TenantId = tenantContext.TenantId,
                EntityType = "PayrollBatch",
                EntityId = batch.Id,
                EventType = EventType.Create,
                ActorUserId = tenantContext.UserId,
                ActorRoles = string.Join(',', tenantContext.Roles),
                OccurredAtUtc = clock.UtcNow,
                ReasonForChange = $"Imported payroll batch {batch.ExternalBatchId}.",
                AfterJson = JsonSerializer.Serialize(new
                {
                    batch.Id,
                    batch.ExternalBatchId,
                    batch.SourceSystem,
                    batch.PeriodStart,
                    batch.PeriodEnd,
                    lineCount = request.Lines.Count
                }),
                CorrelationId = correlation.CorrelationId
            });
        });

        return batch;
    }

    public PayrollBatch ImportBatchFromMappedExtract(PayrollMappedImportBatchRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RawExtract))
        {
            throw new DomainRuleException("Payroll extract content is required.");
        }

        var (profile, lines) = ParseMappedExtract(request.PayrollImportProfileId, request.RawExtract);
        EnsureNoBlockingValidationIssues(ValidateImportLines(lines, profile));
        return ImportBatch(new PayrollImportBatchRequest(
            request.ExternalBatchId,
            profile.SourceSystem,
            request.PeriodStart,
            request.PeriodEnd,
            request.SourceChecksum,
            request.Notes,
            lines));
    }

    public IReadOnlyList<PayrollImportLineRequest> ParseManualLines(string rawLines)
    {
        if (string.IsNullOrWhiteSpace(rawLines))
        {
            throw new DomainRuleException("Payroll line content is required.");
        }

        var parsedLines = new List<PayrollImportLineRequest>();
        foreach (var line in rawLines.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var cells = line.Split(',', StringSplitOptions.TrimEntries);
            if (cells.Length < 5 ||
                !decimal.TryParse(cells[1], out var labor) ||
                !decimal.TryParse(cells[2], out var fringe) ||
                !decimal.TryParse(cells[3], out var tax) ||
                !decimal.TryParse(cells[4], out var other))
            {
                throw new DomainRuleException("Invalid manual line format. Expected: employeeExternalId,labor,fringe,tax,other[,note]");
            }

            var lineNotes = cells.Length > 5 ? string.Join(",", cells.Skip(5)) : null;
            parsedLines.Add(new PayrollImportLineRequest(cells[0], labor, fringe, tax, other, lineNotes));
        }

        if (parsedLines.Count == 0)
        {
            throw new DomainRuleException("No payroll lines were parsed.");
        }

        return parsedLines;
    }

    public (PayrollImportProfile Profile, IReadOnlyList<PayrollImportLineRequest> Lines) ParseMappedExtract(Guid profileId, string rawExtract)
    {
        if (string.IsNullOrWhiteSpace(rawExtract))
        {
            throw new DomainRuleException("Payroll extract content is required.");
        }

        var profile = repository.Query<PayrollImportProfile>(tenantContext.TenantId)
            .SingleOrDefault(x => x.Id == profileId && x.IsActive)
            ?? throw new DomainRuleException("Active payroll import profile not found.");
        var lines = ParseMappedLines(rawExtract, profile);
        return (profile, lines);
    }

    public IReadOnlyList<PayrollImportValidationIssue> ValidateImportLines(IReadOnlyList<PayrollImportLineRequest> lines, PayrollImportProfile? profile)
    {
        var issues = new List<PayrollImportValidationIssue>();
        var usersByExternalId = repository.Query<AppUser>(tenantContext.TenantId)
            .Where(x => !string.IsNullOrWhiteSpace(x.EmployeeExternalId))
            .ToList()
            .GroupBy(x => x.EmployeeExternalId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        var duplicates = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < lines.Count; i++)
        {
            var lineNumber = i + 1;
            var line = lines[i];
            var employeeExternalId = line.EmployeeExternalId?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(employeeExternalId))
            {
                issues.Add(new PayrollImportValidationIssue(lineNumber, string.Empty, "Error", "Employee external id is missing."));
                continue;
            }

            if (!duplicates.TryAdd(employeeExternalId, 1))
            {
                duplicates[employeeExternalId]++;
            }

            if (line.LaborAmount < 0m || line.FringeAmount < 0m || line.TaxAmount < 0m || line.OtherAmount < 0m)
            {
                issues.Add(new PayrollImportValidationIssue(lineNumber, employeeExternalId, "Error", "Negative amount values are not allowed."));
            }

            if (profile?.RequirePositiveLaborAmount == true && line.LaborAmount <= 0m)
            {
                issues.Add(new PayrollImportValidationIssue(lineNumber, employeeExternalId, "Error", "Labor amount must be greater than zero for this profile."));
            }

            var knownEmployee = usersByExternalId.ContainsKey(employeeExternalId);
            if (profile?.RequireKnownEmployeeExternalId == true && !knownEmployee)
            {
                issues.Add(new PayrollImportValidationIssue(lineNumber, employeeExternalId, "Error", "Employee external id is not mapped to a user."));
            }
            else if (!knownEmployee)
            {
                issues.Add(new PayrollImportValidationIssue(lineNumber, employeeExternalId, "Warning", "Employee external id is not mapped to a user."));
            }
        }

        if (profile?.DisallowDuplicateEmployeeExternalIds == true)
        {
            foreach (var dup in duplicates.Where(x => x.Value > 1))
            {
                issues.Add(new PayrollImportValidationIssue(null, dup.Key, "Error", $"Duplicate employee external id appears {dup.Value} times."));
            }
        }

        return issues;
    }

    public IReadOnlyList<PayrollReconciliationRow> Reconciliation(DateOnly? fromDate, DateOnly? toDate)
    {
        var users = repository.Query<AppUser>(tenantContext.TenantId)
            .ToDictionary(x => x.Id, x => x);
        var rates = repository.Query<PersonnelProfile>(tenantContext.TenantId)
            .ToDictionary(x => x.UserId, x => x.HourlyRate);

        var timesheets = repository.Query<Timesheet>(tenantContext.TenantId)
            .Where(x => x.PostedAtUtc.HasValue)
            .Where(x => !fromDate.HasValue || x.PeriodEnd >= fromDate.Value)
            .Where(x => !toDate.HasValue || x.PeriodStart <= toDate.Value)
            .ToList();
        var timesheetById = timesheets.ToDictionary(x => x.Id);
        var timesheetIds = timesheets.Select(x => x.Id).ToHashSet();

        var accrued = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Where(x => timesheetIds.Contains(x.TimesheetId))
            .ToList()
            .GroupBy(x => x.TimesheetId)
            .Select(g =>
            {
                var sheet = timesheetById[g.Key];
                var rate = rates.TryGetValue(sheet.UserId, out var hourlyRate) ? hourlyRate : 0m;
                var labor = Math.Round(g.Sum(x => (x.Minutes / 60m) * rate), 2);
                var user = users[sheet.UserId];
                var externalId = string.IsNullOrWhiteSpace(user.EmployeeExternalId)
                    ? user.Id.ToString("N")
                    : user.EmployeeExternalId;

                return new
                {
                    EmployeeExternalId = externalId,
                    Employee = user.UserName,
                    sheet.PeriodStart,
                    sheet.PeriodEnd,
                    Labor = labor
                };
            })
            .ToList()
            .GroupBy(x => new { x.EmployeeExternalId, x.Employee, x.PeriodStart, x.PeriodEnd })
            .ToDictionary(
                x => (x.Key.EmployeeExternalId, x.Key.PeriodStart, x.Key.PeriodEnd),
                x => new { x.Key.Employee, Labor = Math.Round(x.Sum(v => v.Labor), 2) });

        var batches = repository.Query<PayrollBatch>(tenantContext.TenantId)
            .Where(x => !fromDate.HasValue || x.PeriodEnd >= fromDate.Value)
            .Where(x => !toDate.HasValue || x.PeriodStart <= toDate.Value)
            .ToList();
        var batchesById = batches.ToDictionary(x => x.Id);
        var batchIds = batches.Select(x => x.Id).ToHashSet();

        var payroll = repository.Query<PayrollLine>(tenantContext.TenantId)
            .Where(x => batchIds.Contains(x.PayrollBatchId))
            .ToList()
            .GroupBy(x =>
            {
                var batch = batchesById[x.PayrollBatchId];
                return new { x.EmployeeExternalId, batch.PeriodStart, batch.PeriodEnd };
            })
            .ToDictionary(
                x => (x.Key.EmployeeExternalId, x.Key.PeriodStart, x.Key.PeriodEnd),
                x => Math.Round(x.Sum(v => v.LaborAmount), 2));

        var keys = accrued.Keys.Union(payroll.Keys).ToList();
        return keys
            .Select(key =>
            {
                var hasAccrued = accrued.TryGetValue(key, out var accruedData);
                var accruedLabor = hasAccrued ? accruedData!.Labor : 0m;
                var payrollLabor = payroll.TryGetValue(key, out var pay) ? pay : 0m;
                var variance = Math.Round(payrollLabor - accruedLabor, 2);
                var employee = hasAccrued ? accruedData!.Employee : "(unmapped payroll employee)";
                var status = Math.Abs(variance) < 0.01m ? "Matched" : "Variance";

                return new PayrollReconciliationRow(
                    key.EmployeeExternalId,
                    employee,
                    key.PeriodStart,
                    key.PeriodEnd,
                    accruedLabor,
                    payrollLabor,
                    variance,
                    status);
            })
            .OrderByDescending(x => x.PeriodEnd)
            .ThenBy(x => x.EmployeeExternalId)
            .ToList();
    }

    private static void ValidateColumnMapping(string? value, string label)
    {
        var mapping = value?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(mapping))
        {
            throw new DomainRuleException($"Import mapping for {label} is required.");
        }

        if (mapping.StartsWith('#') &&
            (!int.TryParse(mapping[1..], out var index) || index < 0))
        {
            throw new DomainRuleException($"Import mapping {mapping} for {label} is invalid. Use header name or #<zero-based index>.");
        }
    }

    private static IReadOnlyList<PayrollImportLineRequest> ParseMappedLines(string rawExtract, PayrollImportProfile profile)
    {
        var rows = rawExtract
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (rows.Length == 0)
        {
            throw new DomainRuleException("Payroll extract has no rows.");
        }

        var separator = string.IsNullOrWhiteSpace(profile.Delimiter) ? "," : profile.Delimiter;
        var delimiter = separator[0];
        var headerLookup = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var startRow = 0;

        if (profile.HasHeaderRow)
        {
            var headerCells = rows[0].Split(delimiter, StringSplitOptions.None)
                .Select(NormalizeCell)
                .ToArray();
            for (var i = 0; i < headerCells.Length; i++)
            {
                if (!string.IsNullOrWhiteSpace(headerCells[i]) && !headerLookup.ContainsKey(headerCells[i]))
                {
                    headerLookup[headerCells[i]] = i;
                }
            }

            foreach (var requiredHeader in ParseRequiredHeaders(profile.RequiredHeadersCsv))
            {
                if (!headerLookup.ContainsKey(requiredHeader))
                {
                    throw new DomainRuleException($"Payroll required header '{requiredHeader}' was not found in extract header row.");
                }
            }

            startRow = 1;
        }

        var result = new List<PayrollImportLineRequest>();
        for (var rowIndex = startRow; rowIndex < rows.Length; rowIndex++)
        {
            var row = rows[rowIndex];
            var cells = row.Split(delimiter, StringSplitOptions.None).Select(NormalizeCell).ToArray();

            var employeeExternalId = ResolveCell(cells, profile.EmployeeExternalIdColumn, headerLookup, profile.HasHeaderRow, rowIndex + 1, "EmployeeExternalId");
            if (string.IsNullOrWhiteSpace(employeeExternalId))
            {
                throw new DomainRuleException($"Payroll extract row {rowIndex + 1}: employee external id is required.");
            }

            var labor = ParseAmount(ResolveCell(cells, profile.LaborAmountColumn, headerLookup, profile.HasHeaderRow, rowIndex + 1, "LaborAmount"), rowIndex + 1, "LaborAmount");
            var fringe = ParseAmount(ResolveCell(cells, profile.FringeAmountColumn, headerLookup, profile.HasHeaderRow, rowIndex + 1, "FringeAmount"), rowIndex + 1, "FringeAmount");
            var tax = ParseAmount(ResolveCell(cells, profile.TaxAmountColumn, headerLookup, profile.HasHeaderRow, rowIndex + 1, "TaxAmount"), rowIndex + 1, "TaxAmount");
            var other = ParseAmount(ResolveCell(cells, profile.OtherAmountColumn, headerLookup, profile.HasHeaderRow, rowIndex + 1, "OtherAmount"), rowIndex + 1, "OtherAmount");

            string? notes = null;
            if (!string.IsNullOrWhiteSpace(profile.NotesColumn))
            {
                notes = ResolveCell(cells, profile.NotesColumn!, headerLookup, profile.HasHeaderRow, rowIndex + 1, "Notes");
                if (string.IsNullOrWhiteSpace(notes))
                {
                    notes = null;
                }
            }

            result.Add(new PayrollImportLineRequest(employeeExternalId, labor, fringe, tax, other, notes));
        }

        if (result.Count == 0)
        {
            throw new DomainRuleException("Payroll extract did not produce any import lines.");
        }

        return result;
    }

    private static string ResolveCell(
        string[] cells,
        string mapping,
        Dictionary<string, int> headerLookup,
        bool hasHeader,
        int rowNumber,
        string fieldName)
    {
        var token = mapping.Trim();
        int columnIndex;
        if (token.StartsWith('#'))
        {
            if (!int.TryParse(token[1..], out columnIndex) || columnIndex < 0)
            {
                throw new DomainRuleException($"Payroll mapping {mapping} for {fieldName} is invalid.");
            }
        }
        else
        {
            if (!hasHeader)
            {
                throw new DomainRuleException($"Payroll mapping {mapping} for {fieldName} requires headers; use #<index> when no header row exists.");
            }

            if (!headerLookup.TryGetValue(token, out columnIndex))
            {
                throw new DomainRuleException($"Payroll mapping header '{mapping}' for {fieldName} was not found in extract header row.");
            }
        }

        if (columnIndex >= cells.Length)
        {
            throw new DomainRuleException($"Payroll extract row {rowNumber} does not include mapped column {mapping} for {fieldName}.");
        }

        return cells[columnIndex];
    }

    private static decimal ParseAmount(string raw, int rowNumber, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return 0m;
        }

        if (decimal.TryParse(raw, NumberStyles.Number | NumberStyles.AllowCurrencySymbol, CultureInfo.InvariantCulture, out var amount) ||
            decimal.TryParse(raw, NumberStyles.Number | NumberStyles.AllowCurrencySymbol, CultureInfo.CurrentCulture, out amount))
        {
            if (amount < 0m)
            {
                throw new DomainRuleException($"Payroll extract row {rowNumber} has negative {fieldName}.");
            }

            return amount;
        }

        throw new DomainRuleException($"Payroll extract row {rowNumber} has invalid decimal for {fieldName}: {raw}.");
    }

    private static string NormalizeCell(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2 && trimmed.StartsWith('"') && trimmed.EndsWith('"'))
        {
            return trimmed[1..^1].Trim();
        }

        return trimmed;
    }

    private static IReadOnlyList<string> ParseRequiredHeaders(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv))
        {
            return [];
        }

        return csv.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static void EnsureNoBlockingValidationIssues(IReadOnlyList<PayrollImportValidationIssue> issues)
    {
        var blocking = issues.Where(x => string.Equals(x.Severity, "Error", StringComparison.OrdinalIgnoreCase)).ToList();
        if (blocking.Count == 0)
        {
            return;
        }

        var first = blocking.First();
        var linePrefix = first.LineNumber.HasValue ? $"line {first.LineNumber}: " : string.Empty;
        throw new DomainRuleException($"Payroll import validation failed ({blocking.Count} errors). First error: {linePrefix}{first.Message}");
    }
}
