using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public sealed class JournalEntryWorkflowService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction,
    NotificationService notifications)
{
    public JournalEntry CreateAdjustingEntry(CreateAdjustingJournalEntryRequest request)
    {
        EnsureAccountant();
        ValidateDraftRequest(request);
        EnsurePostingDateOpen(request.EntryDate);

        var entry = new JournalEntry
        {
            TenantId = tenantContext.TenantId,
            EntryDate = request.EntryDate,
            Description = request.Description.Trim(),
            EntryType = JournalEntryType.Adjusting,
            Status = JournalEntryStatus.Draft,
            Reason = request.Reason.Trim(),
            RequestedByUserId = tenantContext.UserId,
            AttachmentRefs = request.AttachmentRefs?.Trim(),
            DraftLinesJson = JsonSerializer.Serialize(request.Lines),
            IsReversal = false
        };

        transaction.Execute(() =>
        {
            repository.Add(entry);
            RecordEvent("JournalEntry", entry.Id, EventType.Create, null, entry, request.Reason);
        });

        return entry;
    }

    public JournalEntry SubmitAdjustingEntry(SubmitAdjustingJournalEntryRequest request)
    {
        EnsureAccountant();
        var reason = NormalizeReason(request.Reason, "Submission reason is required.");
        var entry = GetEntry(request.JournalEntryId);
        EnsureStatus(entry, JournalEntryStatus.Draft, "Only draft entries can be submitted.");
        EnsureHasDraftLines(entry);

        var before = EntrySnapshot(entry);
        entry.Status = JournalEntryStatus.PendingApproval;
        entry.SubmittedAtUtc = clock.UtcNow;
        entry.Reason = reason;

        transaction.Execute(() =>
        {
            repository.Update(entry);
            RecordEvent("JournalEntry", entry.Id, EventType.Submit, before, EntrySnapshot(entry), reason);
        });

        if (RequiresManagerApprovalForAdjustingEntry(entry))
        {
            var amount = AdjustingEntryMagnitude(entry);
            notifications.SendToRole(
                "Manager",
                "Adjusting Entry Pending Manager Approval",
                $"Adjusting entry {entry.Id} amount {amount} requires manager co-sign.",
                "Accounting");
        }

        return entry;
    }

    public JournalEntryApproval ApproveAdjustingEntry(ApproveAdjustingJournalEntryRequest request)
    {
        var reason = NormalizeReason(request.Reason, "Approval reason is required.");
        var entry = GetEntry(request.JournalEntryId);
        EnsureStatus(entry, JournalEntryStatus.PendingApproval, "Only pending entries can be approved.");

        if (entry.RequestedByUserId.HasValue && entry.RequestedByUserId.Value == tenantContext.UserId)
        {
            throw new DomainRuleException("Approver cannot be the same user who requested the adjusting entry.");
        }

        EnsureCanApproveAdjustingEntry(entry);
        var before = EntrySnapshot(entry);
        entry.Status = JournalEntryStatus.Approved;
        entry.ApprovedByUserId = tenantContext.UserId;
        entry.ApprovedAtUtc = clock.UtcNow;
        entry.Reason = reason;
        if (!string.IsNullOrWhiteSpace(request.AttachmentRefs))
        {
            entry.AttachmentRefs = request.AttachmentRefs.Trim();
        }

        var approval = new JournalEntryApproval
        {
            TenantId = tenantContext.TenantId,
            JournalEntryId = entry.Id,
            RequestedByUserId = entry.RequestedByUserId ?? Guid.Empty,
            ApprovedByUserId = tenantContext.UserId,
            ApprovedAtUtc = clock.UtcNow,
            Reason = reason,
            AttachmentRefs = entry.AttachmentRefs
        };

        transaction.Execute(() =>
        {
            repository.Update(entry);
            repository.Add(approval);
            RecordEvent("JournalEntry", entry.Id, EventType.Approve, before, EntrySnapshot(entry), reason);
        });

        return approval;
    }

    public JournalEntry PostApprovedEntry(PostAdjustingJournalEntryRequest request)
    {
        EnsureAccountant();
        var reason = NormalizeReason(request.Reason, "Posting reason is required.");
        var entry = GetEntry(request.JournalEntryId);
        EnsureStatus(entry, JournalEntryStatus.Approved, "Only approved entries can be posted.");
        EnsurePostingDateOpen(entry.EntryDate);

        var lines = ParseDraftLines(entry);
        EnsureBalanced(lines);
        EnsureUniqueAccounts(lines);

        var before = EntrySnapshot(entry);
        transaction.Execute(() =>
        {
            foreach (var line in lines.Where(x => x.Debit != 0m || x.Credit != 0m))
            {
                repository.Add(new JournalLine
                {
                    TenantId = tenantContext.TenantId,
                    JournalEntryId = entry.Id,
                    AccountId = line.AccountId,
                    Debit = Math.Round(line.Debit, 2),
                    Credit = Math.Round(line.Credit, 2)
                });
            }

            entry.Status = JournalEntryStatus.Posted;
            entry.PostedAtUtc = clock.UtcNow;
            entry.Reason = reason;
            repository.Update(entry);
            RecordEvent("JournalEntry", entry.Id, EventType.Post, before, EntrySnapshot(entry), reason);
        });

        return entry;
    }

    public JournalEntry ReverseEntry(ReverseJournalEntryRequest request)
    {
        EnsureAccountant();
        var reason = NormalizeReason(request.Reason, "Reversal reason is required.");
        var entry = GetEntry(request.JournalEntryId);
        if (entry.Status != JournalEntryStatus.Posted)
        {
            throw new DomainRuleException("Only posted entries can be reversed.");
        }

        if (entry.IsReversal)
        {
            throw new DomainRuleException("A reversal entry cannot be reversed again.");
        }

        var existingReversal = repository.Query<JournalEntry>(tenantContext.TenantId)
            .Any(x => x.ReversalOfJournalEntryId == entry.Id && x.Status != JournalEntryStatus.Reversed);
        if (existingReversal)
        {
            throw new DomainRuleException("This entry has already been reversed.");
        }

        var sourceLines = repository.Query<JournalLine>(tenantContext.TenantId)
            .Where(x => x.JournalEntryId == entry.Id)
            .ToList();
        if (sourceLines.Count == 0)
        {
            throw new DomainRuleException("Cannot reverse a posted entry with no journal lines.");
        }

        var reversalDate = request.ReversalDate ?? DateOnly.FromDateTime(clock.UtcNow);
        EnsurePostingDateOpen(reversalDate);
        EnsurePostingDateOpen(entry.EntryDate);

        var reversalEntry = new JournalEntry
        {
            TenantId = tenantContext.TenantId,
            EntryDate = reversalDate,
            Description = $"Reversal of JE {entry.Id}: {entry.Description}",
            EntryType = entry.EntryType,
            Status = JournalEntryStatus.Posted,
            IsReversal = true,
            ReversalOfJournalEntryId = entry.Id,
            RequestedByUserId = tenantContext.UserId,
            ApprovedByUserId = tenantContext.UserId,
            ApprovedAtUtc = clock.UtcNow,
            SubmittedAtUtc = clock.UtcNow,
            PostedAtUtc = clock.UtcNow,
            Reason = reason,
            AttachmentRefs = entry.AttachmentRefs
        };

        var before = EntrySnapshot(entry);
        transaction.Execute(() =>
        {
            repository.Add(reversalEntry);
            foreach (var source in sourceLines)
            {
                repository.Add(new JournalLine
                {
                    TenantId = tenantContext.TenantId,
                    JournalEntryId = reversalEntry.Id,
                    AccountId = source.AccountId,
                    Debit = source.Credit,
                    Credit = source.Debit
                });
            }

            entry.Status = JournalEntryStatus.Reversed;
            repository.Update(entry);

            RecordEvent("JournalEntry", entry.Id, EventType.Reverse, before, EntrySnapshot(entry), reason);
            RecordEvent("JournalEntry", reversalEntry.Id, EventType.Create, null, EntrySnapshot(reversalEntry), reason);
            RecordEvent("JournalEntry", reversalEntry.Id, EventType.Post, null, EntrySnapshot(reversalEntry), reason);
        });

        return reversalEntry;
    }

    private static void ValidateDraftRequest(CreateAdjustingJournalEntryRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Description))
        {
            throw new DomainRuleException("Description is required.");
        }

        _ = NormalizeReason(request.Reason, "Reason is required.");
        if (request.Lines.Count == 0)
        {
            throw new DomainRuleException("At least one journal line is required.");
        }

        EnsureBalanced(request.Lines);
        EnsureUniqueAccounts(request.Lines);
    }

    private static void EnsureBalanced(IReadOnlyList<AdjustingJournalLineRequest> lines)
    {
        if (lines.Any(x => x.AccountId == Guid.Empty))
        {
            throw new DomainRuleException("Account is required for all lines.");
        }

        if (lines.Any(x => x.Debit < 0m || x.Credit < 0m))
        {
            throw new DomainRuleException("Debit and credit values cannot be negative.");
        }

        if (lines.Any(x => x.Debit == 0m && x.Credit == 0m))
        {
            throw new DomainRuleException("Each line must contain a debit or credit amount.");
        }

        if (lines.Any(x => x.Debit > 0m && x.Credit > 0m))
        {
            throw new DomainRuleException("A line cannot contain both debit and credit values.");
        }

        var debit = Math.Round(lines.Sum(x => x.Debit), 2);
        var credit = Math.Round(lines.Sum(x => x.Credit), 2);
        if (debit != credit)
        {
            throw new DomainRuleException("Journal entry is out of balance.");
        }
    }

    private static void EnsureUniqueAccounts(IReadOnlyList<AdjustingJournalLineRequest> lines)
    {
        var duplicateAccount = lines
            .GroupBy(x => x.AccountId)
            .Any(x => x.Count() > 1);
        if (duplicateAccount)
        {
            throw new DomainRuleException("Use one line per account. Combine duplicate account amounts before submitting.");
        }
    }

    private JournalEntry GetEntry(Guid id)
    {
        var entry = repository.Query<JournalEntry>(tenantContext.TenantId).SingleOrDefault(x => x.Id == id)
            ?? throw new DomainRuleException("Journal entry not found.");
        if (entry.EntryType != JournalEntryType.Adjusting)
        {
            throw new DomainRuleException("This workflow only supports adjusting journal entries.");
        }

        return entry;
    }

    private static string NormalizeReason(string? reason, string errorMessage)
    {
        var value = reason?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new DomainRuleException(errorMessage);
        }

        return value;
    }

    private void EnsureAccountant()
    {
        if (!tenantContext.Roles.Contains("Accountant", StringComparer.OrdinalIgnoreCase))
        {
            throw new DomainRuleException("Only accountants can create/submit/post/reverse adjusting journal entries.");
        }
    }

    private void EnsureManager()
    {
        if (!tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase))
        {
            throw new DomainRuleException("Only managers can approve adjusting journal entries.");
        }
    }

    private void EnsureManagerOrAccountant()
    {
        if (tenantContext.Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase) ||
            tenantContext.Roles.Contains("Accountant", StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        throw new DomainRuleException("Only managers or accountants can approve adjusting journal entries.");
    }

    private void EnsureCanApproveAdjustingEntry(JournalEntry entry)
    {
        if (RequiresManagerApprovalForAdjustingEntry(entry))
        {
            EnsureManager();
            return;
        }

        EnsureManagerOrAccountant();
    }

    private bool RequiresManagerApprovalForAdjustingEntry(JournalEntry entry)
    {
        var policy = repository.Query<ManagementReviewPolicy>(tenantContext.TenantId).SingleOrDefault();
        if (policy is null || !policy.RequireManagerCoSignForAdjustingAboveThreshold)
        {
            return false;
        }

        var threshold = Math.Max(0m, policy.AdjustingManagerCoSignThreshold);
        if (threshold <= 0m)
        {
            return false;
        }

        return AdjustingEntryMagnitude(entry) >= threshold;
    }

    private decimal AdjustingEntryMagnitude(JournalEntry entry)
    {
        var lines = ParseDraftLines(entry);
        return Math.Round(lines.Sum(x => x.Debit), 2);
    }

    private static void EnsureStatus(JournalEntry entry, JournalEntryStatus expected, string error)
    {
        if (entry.Status != expected)
        {
            throw new DomainRuleException(error);
        }
    }

    private static void EnsureHasDraftLines(JournalEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.DraftLinesJson))
        {
            throw new DomainRuleException("Draft lines are required.");
        }
    }

    private IReadOnlyList<AdjustingJournalLineRequest> ParseDraftLines(JournalEntry entry)
    {
        try
        {
            var parsed = JsonSerializer.Deserialize<List<AdjustingJournalLineRequest>>(entry.DraftLinesJson ?? string.Empty);
            if (parsed is null || parsed.Count == 0)
            {
                throw new DomainRuleException("Draft lines are invalid.");
            }

            var knownAccounts = repository.Query<ChartOfAccount>(tenantContext.TenantId)
                .Select(x => x.Id)
                .ToHashSet();
            if (parsed.Any(x => !knownAccounts.Contains(x.AccountId)))
            {
                throw new DomainRuleException("One or more account IDs are invalid.");
            }

            return parsed;
        }
        catch (JsonException)
        {
            throw new DomainRuleException("Draft lines are invalid JSON.");
        }
    }

    private void EnsurePostingDateOpen(DateOnly entryDate)
    {
        var period = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .SingleOrDefault(x => entryDate >= x.StartDate && entryDate <= x.EndDate);
        if (period is not null && period.Status == AccountingPeriodStatus.Closed)
        {
            throw new DomainRuleException("Cannot post journal entries into a closed accounting period.");
        }
    }

    private object EntrySnapshot(JournalEntry entry)
    {
        return new
        {
            entry.Id,
            entry.EntryDate,
            entry.Description,
            entry.EntryType,
            entry.Status,
            entry.IsReversal,
            entry.ReversalOfJournalEntryId,
            entry.RequestedByUserId,
            entry.SubmittedAtUtc,
            entry.ApprovedByUserId,
            entry.ApprovedAtUtc,
            entry.PostedAtUtc,
            entry.Reason,
            entry.AttachmentRefs
        };
    }

    private void RecordEvent(string entityType, Guid entityId, EventType eventType, object? before, object? after, string? reason = null)
    {
        audit.Record(new AuditEvent
        {
            TenantId = tenantContext.TenantId,
            EntityType = entityType,
            EntityId = entityId,
            EventType = eventType,
            ActorUserId = tenantContext.UserId,
            ActorRoles = string.Join(',', tenantContext.Roles),
            OccurredAtUtc = clock.UtcNow,
            ReasonForChange = reason,
            BeforeJson = before is null ? null : JsonSerializer.Serialize(before),
            AfterJson = after is null ? null : JsonSerializer.Serialize(after),
            CorrelationId = correlation.CorrelationId
        });
    }
}
