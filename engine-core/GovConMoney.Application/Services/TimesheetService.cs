using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Models;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public class TimesheetService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction,
    TimecardValidationEngine? validationEngine = null,
    NotificationService? notifications = null)
{
    private readonly TimecardValidationEngine _validationEngine = validationEngine ?? new TimecardValidationEngine(repository, tenantContext);
    private readonly NotificationService? _notifications = notifications;

    public Timesheet CreateTimesheetDraft(CreateTimesheetRequest request)
    {
        if (request.PeriodEnd < request.PeriodStart)
        {
            throw new DomainRuleException("Timesheet period end must be on or after start.");
        }

        var creationIssues = _validationEngine.ValidateDraftCreation(tenantContext.UserId, request.PeriodStart, request.PeriodEnd);
        if (creationIssues.Count > 0)
        {
            throw new DomainRuleException(string.Join(" ", creationIssues));
        }

        var timesheet = new Timesheet
        {
            TenantId = tenantContext.TenantId,
            UserId = tenantContext.UserId,
            PeriodStart = request.PeriodStart,
            PeriodEnd = request.PeriodEnd,
            Status = TimesheetStatus.Draft
        };

        transaction.Execute(() =>
        {
            repository.Add(timesheet);
            RecordEvent("Timesheet", timesheet.Id, EventType.Create, null, timesheet);
        });

        return timesheet;
    }

    public TimesheetLine AddLine(Guid timesheetId, AddTimesheetLineRequest request)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);
        EnsureInPeriod(timesheet, request.WorkDate);
        EnsureAccountingPeriodOpen(request.WorkDate);
        ValidateTimesheetLineRequest(timesheet, request.WorkDate, request.Minutes, request.EntryType);

        var chargeCodeId = request.EntryType == TimesheetEntryType.Work ? request.ChargeCodeId : Guid.Empty;
        var costType = request.EntryType == TimesheetEntryType.Work ? request.CostType : CostType.Unallowable;

        if (request.EntryType == TimesheetEntryType.Work)
        {
            var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.ChargeCodeId)
                ?? throw new DomainRuleException("Charge code not found.");
            if (!chargeCode.IsActive)
            {
                throw new DomainRuleException("Charge code is inactive.");
            }
        }

        EnsureUserCanChargeCode(timesheet.UserId, chargeCodeId, request.WorkDate, request.EntryType);

        var line = new TimesheetLine
        {
            TenantId = timesheet.TenantId,
            TimesheetId = timesheet.Id,
            WorkDate = request.WorkDate,
            ChargeCodeId = chargeCodeId,
            Minutes = request.Minutes,
            CostType = costType,
            EntryType = request.EntryType,
            Comment = request.Comment
        };

        transaction.Execute(() =>
        {
            repository.Add(line);
            RecordEvent("TimesheetLine", line.Id, EventType.UpdateDraft, null, line);
        });

        return line;
    }

    public TimesheetLine UpdateLine(Guid timesheetId, Guid lineId, UpdateTimesheetLineRequest request)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);

        var line = repository.Query<TimesheetLine>(tenantContext.TenantId).SingleOrDefault(x => x.Id == lineId && x.TimesheetId == timesheetId)
            ?? throw new DomainRuleException("Timesheet line not found.");

        EnsureInPeriod(timesheet, request.WorkDate);
        EnsureAccountingPeriodOpen(request.WorkDate);
        ValidateTimesheetLineRequest(timesheet, request.WorkDate, request.Minutes, request.EntryType);

        var chargeCodeId = request.EntryType == TimesheetEntryType.Work ? request.ChargeCodeId : Guid.Empty;
        var costType = request.EntryType == TimesheetEntryType.Work ? request.CostType : CostType.Unallowable;

        if (request.EntryType == TimesheetEntryType.Work)
        {
            var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.ChargeCodeId)
                ?? throw new DomainRuleException("Charge code not found.");
            if (!chargeCode.IsActive)
            {
                throw new DomainRuleException("Charge code is inactive.");
            }
        }

        EnsureUserCanChargeCode(timesheet.UserId, chargeCodeId, request.WorkDate, request.EntryType);

        var before = new
        {
            line.Id,
            line.WorkDate,
            line.ChargeCodeId,
            line.Minutes,
            line.CostType,
            line.EntryType,
            line.Comment
        };

        line.WorkDate = request.WorkDate;
        line.ChargeCodeId = chargeCodeId;
        line.Minutes = request.Minutes;
        line.CostType = costType;
        line.EntryType = request.EntryType;
        line.Comment = request.Comment;

        transaction.Execute(() =>
        {
            repository.Update(line);
            RecordEvent("TimesheetLine", line.Id, EventType.UpdateDraft, before, line);
        });

        return line;
    }

    public TimesheetExpense AddExpense(Guid timesheetId, AddTimesheetExpenseRequest request)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);
        EnsureInPeriod(timesheet, request.ExpenseDate);
        EnsureAccountingPeriodOpen(request.ExpenseDate);

        if (request.Amount <= 0m)
        {
            throw new DomainRuleException("Expense amount must be greater than zero.");
        }

        var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.ChargeCodeId)
            ?? throw new DomainRuleException("Charge code not found.");
        if (!chargeCode.IsActive)
        {
            throw new DomainRuleException("Charge code is inactive.");
        }

        EnsureUserCanChargeCode(timesheet.UserId, request.ChargeCodeId, request.ExpenseDate, TimesheetEntryType.Work);

        var expense = new TimesheetExpense
        {
            TenantId = timesheet.TenantId,
            TimesheetId = timesheet.Id,
            ExpenseDate = request.ExpenseDate,
            ChargeCodeId = request.ChargeCodeId,
            Amount = request.Amount,
            CostType = request.CostType,
            Category = request.Category?.Trim() ?? string.Empty,
            Description = request.Description?.Trim() ?? string.Empty,
            Status = ExpenseStatus.PendingApproval
        };

        transaction.Execute(() =>
        {
            repository.Add(expense);
            RecordEvent("TimesheetExpense", expense.Id, EventType.UpdateDraft, null, expense);
        });

        return expense;
    }

    public TimesheetExpense UpdateExpense(Guid timesheetId, Guid expenseId, UpdateTimesheetExpenseRequest request)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);

        var expense = repository.Query<TimesheetExpense>(tenantContext.TenantId).SingleOrDefault(x => x.Id == expenseId && x.TimesheetId == timesheetId)
            ?? throw new DomainRuleException("Timesheet expense not found.");

        EnsureInPeriod(timesheet, request.ExpenseDate);
        EnsureAccountingPeriodOpen(request.ExpenseDate);

        if (request.Amount <= 0m)
        {
            throw new DomainRuleException("Expense amount must be greater than zero.");
        }

        var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == request.ChargeCodeId)
            ?? throw new DomainRuleException("Charge code not found.");
        if (!chargeCode.IsActive)
        {
            throw new DomainRuleException("Charge code is inactive.");
        }

        EnsureUserCanChargeCode(timesheet.UserId, request.ChargeCodeId, request.ExpenseDate, TimesheetEntryType.Work);

        var before = new
        {
            expense.Id,
            expense.ExpenseDate,
            expense.ChargeCodeId,
            expense.Amount,
            expense.CostType,
            expense.Category,
            expense.Description
        };

        expense.ExpenseDate = request.ExpenseDate;
        expense.ChargeCodeId = request.ChargeCodeId;
        expense.Amount = request.Amount;
        expense.CostType = request.CostType;
        expense.Category = request.Category?.Trim() ?? string.Empty;
        expense.Description = request.Description?.Trim() ?? string.Empty;
        expense.Status = ExpenseStatus.PendingApproval;
        expense.ApprovedByUserId = null;
        expense.ApprovedAtUtc = null;
        expense.RejectionReason = null;

        transaction.Execute(() =>
        {
            repository.Update(expense);
            RecordEvent("TimesheetExpense", expense.Id, EventType.UpdateDraft, before, expense);
        });

        return expense;
    }

    public void DeleteExpense(Guid timesheetId, Guid expenseId)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);

        var expense = repository.Query<TimesheetExpense>(tenantContext.TenantId).SingleOrDefault(x => x.Id == expenseId && x.TimesheetId == timesheetId)
            ?? throw new DomainRuleException("Timesheet expense not found.");

        var before = new
        {
            expense.Status,
            expense.VoidReason,
            expense.VoidedAtUtc,
            expense.VoidedByUserId
        };

        expense.Status = ExpenseStatus.Voided;
        expense.VoidReason = "Voided in draft";
        expense.VoidedAtUtc = clock.UtcNow;
        expense.VoidedByUserId = tenantContext.UserId;

        transaction.Execute(() =>
        {
            repository.Update(expense);
            RecordEvent("TimesheetExpense", expense.Id, EventType.Reject, before, expense, expense.VoidReason);
        });
    }

    public TimesheetExpense VoidExpense(Guid timesheetId, Guid expenseId, string reason)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);

        var expense = repository.Query<TimesheetExpense>(tenantContext.TenantId).SingleOrDefault(x => x.Id == expenseId && x.TimesheetId == timesheetId)
            ?? throw new DomainRuleException("Timesheet expense not found.");

        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Void reason is required.");
        }

        var before = new
        {
            expense.Status,
            expense.VoidReason,
            expense.VoidedAtUtc,
            expense.VoidedByUserId
        };

        expense.Status = ExpenseStatus.Voided;
        expense.VoidReason = reason.Trim();
        expense.VoidedAtUtc = clock.UtcNow;
        expense.VoidedByUserId = tenantContext.UserId;

        transaction.Execute(() =>
        {
            repository.Update(expense);
            RecordEvent("TimesheetExpense", expense.Id, EventType.Reject, before, expense, expense.VoidReason);
        });

        return expense;
    }

    public TimesheetExpense ApproveExpense(Guid timesheetId, Guid expenseId)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureSupervisorAssigned(timesheet);

        var expense = repository.Query<TimesheetExpense>(tenantContext.TenantId).SingleOrDefault(x => x.Id == expenseId && x.TimesheetId == timesheetId)
            ?? throw new DomainRuleException("Timesheet expense not found.");

        var before = new
        {
            expense.Status,
            expense.ApprovedByUserId,
            expense.ApprovedAtUtc
        };

        expense.Status = ExpenseStatus.Approved;
        expense.ApprovedByUserId = tenantContext.UserId;
        expense.ApprovedAtUtc = clock.UtcNow;
        expense.RejectionReason = null;

        transaction.Execute(() =>
        {
            repository.Update(expense);
            RecordEvent("TimesheetExpense", expense.Id, EventType.Approve, before, expense);
        });

        return expense;
    }

    public TimesheetExpense RejectExpense(Guid timesheetId, Guid expenseId, string reason)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureSupervisorAssigned(timesheet);

        var expense = repository.Query<TimesheetExpense>(tenantContext.TenantId).SingleOrDefault(x => x.Id == expenseId && x.TimesheetId == timesheetId)
            ?? throw new DomainRuleException("Timesheet expense not found.");

        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Rejection reason is required.");
        }

        var before = new
        {
            expense.Status,
            expense.RejectionReason
        };

        expense.Status = ExpenseStatus.Rejected;
        expense.RejectionReason = reason.Trim();
        expense.ApprovedByUserId = tenantContext.UserId;
        expense.ApprovedAtUtc = clock.UtcNow;

        transaction.Execute(() =>
        {
            repository.Update(expense);
            RecordEvent("TimesheetExpense", expense.Id, EventType.Reject, before, expense, expense.RejectionReason);
        });

        return expense;
    }

    public TimesheetExpense AssignExpenseAccountingCategory(Guid expenseId, ExpenseAccountingCategory accountingCategory, string? reason)
    {
        var expense = repository.Query<TimesheetExpense>(tenantContext.TenantId).SingleOrDefault(x => x.Id == expenseId)
            ?? throw new DomainRuleException("Timesheet expense not found.");
        var timesheet = GetTimesheet(expense.TimesheetId);
        if (timesheet.Status == TimesheetStatus.Draft)
        {
            throw new DomainRuleException("Accounting category can only be assigned after time card submission.");
        }

        var before = new
        {
            expense.AccountingCategory,
            expense.AccountingCategoryAssignedByUserId,
            expense.AccountingCategoryAssignedAtUtc
        };

        expense.AccountingCategory = accountingCategory;
        expense.AccountingCategoryAssignedByUserId = tenantContext.UserId;
        expense.AccountingCategoryAssignedAtUtc = clock.UtcNow;

        transaction.Execute(() =>
        {
            repository.Update(expense);
            RecordEvent("TimesheetExpense", expense.Id, EventType.ExpenseAccountingCategoryAssignment, before, expense, reason);
        });

        return expense;
    }

    public void Submit(SubmitTimesheetRequest request)
    {
        var timesheet = GetTimesheet(request.TimesheetId);
        EnsureDraft(timesheet);

        var validationIssues = _validationEngine.ValidateSubmission(timesheet);
        if (validationIssues.Count > 0)
        {
            var beforeFailed = Snapshot(timesheet);
            timesheet.IsComplianceFlagged = true;
            timesheet.ComplianceIssuesJson = JsonSerializer.Serialize(validationIssues);
            timesheet.LastComplianceCheckedAtUtc = clock.UtcNow;

            transaction.Execute(() =>
            {
                repository.Update(timesheet);
                RecordEvent("Timesheet", timesheet.Id, EventType.Reject, beforeFailed, timesheet, string.Join(" | ", validationIssues));
            });

            throw new DomainRuleException($"Time card failed compliance validation: {string.Join(" ", validationIssues)}");
        }

        var before = Snapshot(timesheet);
        timesheet.Status = TimesheetStatus.Submitted;
        timesheet.SubmittedAtUtc = clock.UtcNow;
        timesheet.Attestation = request.Attestation;
        timesheet.IsComplianceFlagged = false;
        timesheet.ComplianceIssuesJson = null;
        timesheet.LastComplianceCheckedAtUtc = clock.UtcNow;

        transaction.Execute(() =>
        {
            repository.Update(timesheet);
            RecordEvent("Timesheet", timesheet.Id, EventType.Submit, before, timesheet);
        });
    }

    public TimesheetWorkNote AddWorkNote(Guid timesheetId, AddWorkNoteRequest request)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);

        var noteText = request.Note?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(noteText))
        {
            throw new DomainRuleException("Work note is required.");
        }

        var note = new TimesheetWorkNote
        {
            TenantId = tenantContext.TenantId,
            TimesheetId = timesheet.Id,
            CreatedByUserId = tenantContext.UserId,
            Note = noteText
        };

        transaction.Execute(() =>
        {
            repository.Add(note);
            RecordEvent("TimesheetWorkNote", note.Id, EventType.UpdateDraft, null, note);
        });

        return note;
    }

    public WeeklyStatusReport UpsertWeeklyStatusReport(Guid timesheetId, UpsertWeeklyStatusReportRequest request)
    {
        var timesheet = GetTimesheet(timesheetId);
        EnsureDraft(timesheet);

        var narrative = request.Narrative?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(narrative))
        {
            throw new DomainRuleException("Weekly status narrative is required.");
        }

        var existing = repository.Query<WeeklyStatusReport>(tenantContext.TenantId)
            .SingleOrDefault(x => x.TimesheetId == timesheet.Id);

        if (existing is null)
        {
            var created = new WeeklyStatusReport
            {
                TenantId = tenantContext.TenantId,
                TimesheetId = timesheet.Id,
                UserId = tenantContext.UserId,
                Narrative = narrative,
                UpdatedAtUtc = clock.UtcNow
            };

            transaction.Execute(() =>
            {
                repository.Add(created);
                RecordEvent("WeeklyStatusReport", created.Id, EventType.UpdateDraft, null, created);
            });

            return created;
        }

        var before = new { existing.Narrative, existing.UpdatedAtUtc };
        existing.Narrative = narrative;
        existing.UpdatedAtUtc = clock.UtcNow;

        transaction.Execute(() =>
        {
            repository.Update(existing);
            RecordEvent("WeeklyStatusReport", existing.Id, EventType.UpdateDraft, before, existing);
        });

        return existing;
    }

    public FuturePtoApprovalRequest RequestFuturePtoApproval(Guid timesheetId, DateOnly workDate, string? reason = null)
    {
        var timesheet = GetTimesheet(timesheetId);
        if (timesheet.UserId != tenantContext.UserId)
        {
            throw new DomainRuleException("Only the owner can request future PTO approval.");
        }

        if (timesheet.Status != TimesheetStatus.Draft && timesheet.Status != TimesheetStatus.Submitted)
        {
            throw new DomainRuleException("Future PTO approval can only be requested for draft or submitted timesheets.");
        }

        EnsureInPeriod(timesheet, workDate);
        var today = DateOnly.FromDateTime(clock.UtcNow.Date);
        if (workDate <= today)
        {
            throw new DomainRuleException("Future PTO approval requests are only for future dates.");
        }

        var hasFuturePto = repository.Query<TimesheetLine>(tenantContext.TenantId)
            .Any(x => x.TimesheetId == timesheetId && x.EntryType == TimesheetEntryType.Pto && x.WorkDate == workDate);
        if (!hasFuturePto)
        {
            throw new DomainRuleException("Add a future PTO line for the date before requesting approval.");
        }

        var alreadyApproved = repository.Query<FuturePtoApproval>(tenantContext.TenantId)
            .Any(x => x.UserId == timesheet.UserId && x.WorkDate == workDate);
        if (alreadyApproved)
        {
            throw new DomainRuleException("Future PTO is already approved for that date.");
        }

        var profile = repository.Query<PersonnelProfile>(tenantContext.TenantId)
            .SingleOrDefault(x => x.UserId == timesheet.UserId)
            ?? throw new DomainRuleException("Personnel profile missing for employee.");
        if (!profile.SupervisorUserId.HasValue)
        {
            throw new DomainRuleException("A supervisor must be assigned before requesting future PTO approval.");
        }

        var requestReason = string.IsNullOrWhiteSpace(reason)
            ? "Future PTO approval requested by employee."
            : reason.Trim();

        var existing = repository.Query<FuturePtoApprovalRequest>(tenantContext.TenantId)
            .SingleOrDefault(x => x.UserId == timesheet.UserId && x.WorkDate == workDate);

        FuturePtoApprovalRequest requestEntity;
        if (existing is null)
        {
            requestEntity = new FuturePtoApprovalRequest
            {
                TenantId = tenantContext.TenantId,
                UserId = timesheet.UserId,
                WorkDate = workDate,
                RequestedByUserId = tenantContext.UserId,
                Reason = requestReason,
                RequestedAtUtc = clock.UtcNow
            };
        }
        else
        {
            requestEntity = existing;
            requestEntity.Reason = requestReason;
            requestEntity.RequestedAtUtc = clock.UtcNow;
        }

        transaction.Execute(() =>
        {
            if (existing is null)
            {
                repository.Add(requestEntity);
            }
            else
            {
                repository.Update(requestEntity);
            }

            RecordEvent(
                "FuturePtoApprovalRequest",
                requestEntity.Id,
                EventType.FuturePtoApprovalRequest,
                null,
                requestEntity,
                requestReason);

            _notifications?.SendToUser(
                profile.SupervisorUserId.Value,
                "Future PTO Approval Requested",
                $"{timesheet.UserId} requested future PTO approval for {workDate:yyyy-MM-dd}. Reason: {requestReason}",
                "FuturePtoApproval");
        });

        return requestEntity;
    }

    public void Approve(ApproveTimesheetRequest request)
    {
        var timesheet = GetTimesheet(request.TimesheetId);
        if (timesheet.Status != TimesheetStatus.Submitted)
        {
            throw new DomainRuleException("Only submitted timesheets can be approved.");
        }

        if (timesheet.UserId == tenantContext.UserId)
        {
            throw new DomainRuleException("A user cannot approve their own timesheet.");
        }

        EnsureSupervisorAssigned(timesheet);

        var unapprovedExpenses = repository.Query<TimesheetExpense>(tenantContext.TenantId)
            .Where(x => x.TimesheetId == timesheet.Id && x.Status != ExpenseStatus.Approved && x.Status != ExpenseStatus.Voided)
            .ToList();
        if (unapprovedExpenses.Count > 0)
        {
            throw new DomainRuleException("All expenses must be approved (or voided) before timesheet approval.");
        }

        var before = Snapshot(timesheet);
        timesheet.Status = TimesheetStatus.Approved;
        timesheet.ApprovedByUserId = tenantContext.UserId;
        timesheet.ApprovedAtUtc = clock.UtcNow;

        transaction.Execute(() =>
        {
            repository.Update(timesheet);
            repository.Add(new TimesheetApproval
            {
                TenantId = tenantContext.TenantId,
                TimesheetId = timesheet.Id,
                ApproverUserId = tenantContext.UserId,
                ApprovedAtUtc = clock.UtcNow
            });

            RecordEvent("Timesheet", timesheet.Id, EventType.Approve, before, timesheet);
        });
    }

    public CorrectionRequest RequestCorrection(RequestCorrectionRequest request)
    {
        var timesheet = GetTimesheet(request.TimesheetId);
        if (string.IsNullOrWhiteSpace(request.ReasonForChange))
        {
            throw new DomainRuleException("Correction reason is required.");
        }

        if (timesheet.Status == TimesheetStatus.Draft)
        {
            throw new DomainRuleException("Draft timesheets do not require correction workflow.");
        }

        var correction = new CorrectionRequest
        {
            TenantId = tenantContext.TenantId,
            TimesheetId = timesheet.Id,
            RequestedByUserId = tenantContext.UserId,
            ReasonForChange = request.ReasonForChange,
            Approved = true
        };

        transaction.Execute(() =>
        {
            repository.Add(correction);
            repository.Add(new CorrectionApproval
            {
                TenantId = tenantContext.TenantId,
                CorrectionRequestId = correction.Id,
                ApproverUserId = tenantContext.UserId,
                ApprovedAtUtc = clock.UtcNow
            });
            RecordEvent("Timesheet", timesheet.Id, EventType.Correct, null, correction, request.ReasonForChange);
        });

        return correction;
    }

    public Timesheet ApplyCorrection(ApplyCorrectionRequest request)
    {
        var reason = request.ReasonForChange;
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Correction reason is required.");
        }

        var source = GetTimesheet(request.TimesheetId);
        var correction = repository.Query<CorrectionRequest>(tenantContext.TenantId)
            .SingleOrDefault(x => x.Id == request.CorrectionRequestId && x.TimesheetId == source.Id && x.Approved)
            ?? throw new DomainRuleException("Approved correction request not found.");

        if (source.Status == TimesheetStatus.Draft)
        {
            throw new DomainRuleException("Draft timesheets cannot be corrected.");
        }

        var newVersion = new Timesheet
        {
            TenantId = source.TenantId,
            UserId = source.UserId,
            PeriodStart = source.PeriodStart,
            PeriodEnd = source.PeriodEnd,
            Status = TimesheetStatus.Draft,
            VersionNumber = source.VersionNumber + 1
        };

        transaction.Execute(() =>
        {
            repository.Add(newVersion);
            foreach (var line in request.NewLines)
            {
                AddLineInternal(newVersion, line);
            }
            var sourceExpenses = repository.Query<TimesheetExpense>(tenantContext.TenantId)
                .Where(x => x.TimesheetId == source.Id)
                .ToList();
            foreach (var sourceExpense in sourceExpenses)
            {
                repository.Add(new TimesheetExpense
                {
                    TenantId = sourceExpense.TenantId,
                    TimesheetId = newVersion.Id,
                    ExpenseDate = sourceExpense.ExpenseDate,
                    ChargeCodeId = sourceExpense.ChargeCodeId,
                    CostType = sourceExpense.CostType,
                    Amount = sourceExpense.Amount,
                    Category = sourceExpense.Category,
                    Description = sourceExpense.Description,
                    AccountingCategory = sourceExpense.AccountingCategory,
                    AccountingCategoryAssignedByUserId = sourceExpense.AccountingCategoryAssignedByUserId,
                    AccountingCategoryAssignedAtUtc = sourceExpense.AccountingCategoryAssignedAtUtc,
                    Status = sourceExpense.Status,
                    ApprovedByUserId = sourceExpense.ApprovedByUserId,
                    ApprovedAtUtc = sourceExpense.ApprovedAtUtc,
                    RejectionReason = sourceExpense.RejectionReason,
                    VoidedByUserId = sourceExpense.VoidedByUserId,
                    VoidedAtUtc = sourceExpense.VoidedAtUtc,
                    VoidReason = sourceExpense.VoidReason
                });
            }

            repository.Add(new TimesheetVersion
            {
                TenantId = source.TenantId,
                TimesheetId = source.Id,
                VersionNumber = source.VersionNumber,
                SnapshotJson = JsonSerializer.Serialize(source)
            });

            source.Status = TimesheetStatus.Corrected;
            repository.Update(source);

            RecordEvent("Timesheet", source.Id, EventType.Correct, source, newVersion, correction.ReasonForChange);
        });

        return newVersion;
    }

    private void AddLineInternal(Timesheet timesheet, AddTimesheetLineRequest request)
    {
        EnsureInPeriod(timesheet, request.WorkDate);
        EnsureAccountingPeriodOpen(request.WorkDate);
        ValidateTimesheetLineRequest(timesheet, request.WorkDate, request.Minutes, request.EntryType);

        var chargeCodeId = request.EntryType == TimesheetEntryType.Work ? request.ChargeCodeId : Guid.Empty;
        var costType = request.EntryType == TimesheetEntryType.Work ? request.CostType : CostType.Unallowable;
        EnsureUserCanChargeCode(timesheet.UserId, chargeCodeId, request.WorkDate, request.EntryType);

        repository.Add(new TimesheetLine
        {
            TenantId = timesheet.TenantId,
            TimesheetId = timesheet.Id,
            WorkDate = request.WorkDate,
            ChargeCodeId = chargeCodeId,
            Minutes = request.Minutes,
            CostType = costType,
            EntryType = request.EntryType,
            Comment = request.Comment
        });
    }

    private void EnsureUserCanChargeCode(Guid userId, Guid chargeCodeId, DateOnly workDate, TimesheetEntryType entryType)
    {
        if (entryType != TimesheetEntryType.Work)
        {
            return;
        }

        var assignmentInWindow = repository.Query<Assignment>(tenantContext.TenantId)
            .Any(x => x.UserId == userId && x.ChargeCodeId == chargeCodeId && workDate >= x.EffectiveStartDate && workDate <= x.EffectiveEndDate);

        if (assignmentInWindow)
        {
            return;
        }

        var overrideAllowed = repository.Query<Assignment>(tenantContext.TenantId)
            .Any(x => x.UserId == userId && x.ChargeCodeId == chargeCodeId && x.SupervisorOverrideAllowed);

        if (!overrideAllowed)
        {
            throw new DomainRuleException("User is not assigned to the charge code for the work date.");
        }

        var overrideApprovalExists = repository.Query<TimeChargeOverrideApproval>(tenantContext.TenantId)
            .Any(x => x.UserId == userId && x.ChargeCodeId == chargeCodeId && x.WorkDate == workDate);

        if (!overrideApprovalExists)
        {
            throw new DomainRuleException("Out-of-window charging requires supervisor override approval.");
        }
    }

    private void ValidateTimesheetLineRequest(Timesheet timesheet, DateOnly workDate, int minutes, TimesheetEntryType entryType)
    {
        var today = DateOnly.FromDateTime(clock.UtcNow);
        switch (entryType)
        {
            case TimesheetEntryType.NoTime:
                if (minutes != 0)
                {
                    throw new DomainRuleException("No-time entry must have exactly 0 minutes.");
                }

                if (workDate > today)
                {
                    throw new DomainRuleException("Future-dated no-time entry is not allowed.");
                }

                break;
            case TimesheetEntryType.Pto:
                if (minutes <= 0 || minutes > 24 * 60)
                {
                    throw new DomainRuleException("PTO minutes must be between 1 and 1440.");
                }

                if (workDate > today)
                {
                    // Future PTO can be entered, but requires supervisor approval before submission.
                    return;
                }

                break;
            case TimesheetEntryType.Holiday:
                if (minutes <= 0 || minutes > 24 * 60)
                {
                    throw new DomainRuleException("Holiday minutes must be between 1 and 1440.");
                }

                if (workDate > today)
                {
                    throw new DomainRuleException("Future-dated holiday entry is not allowed.");
                }

                break;
            case TimesheetEntryType.Work:
            default:
                if (minutes <= 0 || minutes > 24 * 60)
                {
                    throw new DomainRuleException("Minutes must be between 1 and 1440.");
                }

                if (workDate > today)
                {
                    throw new DomainRuleException("Future-dated work entry is not allowed.");
                }

                break;
        }
    }

    private void EnsureAccountingPeriodOpen(DateOnly workDate)
    {
        var coveringPeriod = repository.Query<AccountingPeriod>(tenantContext.TenantId)
            .SingleOrDefault(x => workDate >= x.StartDate && workDate <= x.EndDate);

        if (coveringPeriod is not null && coveringPeriod.Status == AccountingPeriodStatus.Closed)
        {
            throw new DomainRuleException("Cannot charge time in a closed accounting period.");
        }
    }

    private static object Snapshot(Timesheet timesheet) => new
    {
        timesheet.Id,
        timesheet.Status,
        timesheet.SubmittedAtUtc,
        timesheet.ApprovedAtUtc,
        timesheet.VersionNumber
    };

    private void EnsureInPeriod(Timesheet timesheet, DateOnly workDate)
    {
        if (workDate < timesheet.PeriodStart || workDate > timesheet.PeriodEnd)
        {
            throw new DomainRuleException("Work date is outside timesheet period.");
        }
    }

    private static void EnsureDraft(Timesheet timesheet)
    {
        if (timesheet.Status != TimesheetStatus.Draft)
        {
            throw new DomainRuleException("Submitted or approved timesheets are locked and cannot be edited directly.");
        }
    }

    private Timesheet GetTimesheet(Guid timesheetId)
    {
        return repository.Query<Timesheet>(tenantContext.TenantId).SingleOrDefault(x => x.Id == timesheetId)
            ?? throw new DomainRuleException("Timesheet not found.");
    }

    private void EnsureSupervisorAssigned(Timesheet timesheet)
    {
        var profile = repository.Query<PersonnelProfile>(tenantContext.TenantId).SingleOrDefault(x => x.UserId == timesheet.UserId)
            ?? throw new DomainRuleException("Personnel profile missing for employee.");

        if (profile.SupervisorUserId != tenantContext.UserId)
        {
            throw new DomainRuleException("Supervisor is not assigned to approve this employee.");
        }
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
