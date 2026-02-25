using GovConMoney.Application.Abstractions;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using System.Text.Json;

namespace GovConMoney.Application.Services;

public class ComplianceService(
    IRepository repository,
    ITenantContext tenantContext,
    IAuditService audit,
    ICorrelationContext correlation,
    IClock clock,
    IAppTransaction transaction,
    NotificationService? notifications = null)
{
    private readonly NotificationService? _notifications = notifications;

    public Contract CreateContract(string contractNumber, string name, decimal budget, ContractType contractType)
    {
        var start = DateOnly.FromDateTime(clock.UtcNow.Date);
        var end = start.AddYears(1).AddDays(-1);
        return CreateContract(contractNumber, name, budget, contractType, start, end, false);
    }

    public Contract CreateContract(string contractNumber, string name, decimal budget, ContractType contractType, DateOnly baseYearStartDate, DateOnly baseYearEndDate, bool requiresClinTracking = false)
    {
        if (baseYearEndDate < baseYearStartDate)
        {
            throw new DomainRuleException("Base year end date must be on or after start date.");
        }

        var contract = new Contract
        {
            TenantId = tenantContext.TenantId,
            ContractNumber = contractNumber,
            Name = name,
            BudgetAmount = budget,
            ContractType = contractType,
            RequiresClinTracking = requiresClinTracking,
            BaseYearStartDate = baseYearStartDate,
            BaseYearEndDate = baseYearEndDate
        };

        transaction.Execute(() =>
        {
            repository.Add(contract);
            WriteAudit("Contract", contract.Id, EventType.Create, null, contract);
        });
        return contract;
    }

    public Contract UpdateContract(Guid contractId, string contractNumber, string name, decimal budget, ContractType contractType)
    {
        var contract = repository.Query<Contract>(tenantContext.TenantId).SingleOrDefault(x => x.Id == contractId)
            ?? throw new DomainRuleException("Contract not found.");
        return UpdateContract(contractId, contractNumber, name, budget, contractType, contract.BaseYearStartDate, contract.BaseYearEndDate, contract.RequiresClinTracking);
    }

    public Contract UpdateContract(Guid contractId, string contractNumber, string name, decimal budget, ContractType contractType, DateOnly baseYearStartDate, DateOnly baseYearEndDate, bool requiresClinTracking = false)
    {
        var contract = repository.Query<Contract>(tenantContext.TenantId).SingleOrDefault(x => x.Id == contractId)
            ?? throw new DomainRuleException("Contract not found.");

        if (baseYearEndDate < baseYearStartDate)
        {
            throw new DomainRuleException("Base year end date must be on or after start date.");
        }

        var before = new { contract.ContractNumber, contract.Name, contract.BudgetAmount, contract.ContractType, contract.RequiresClinTracking, contract.BaseYearStartDate, contract.BaseYearEndDate };
        contract.ContractNumber = contractNumber;
        contract.Name = name;
        contract.BudgetAmount = budget;
        contract.ContractType = contractType;
        contract.RequiresClinTracking = requiresClinTracking;
        contract.BaseYearStartDate = baseYearStartDate;
        contract.BaseYearEndDate = baseYearEndDate;
        transaction.Execute(() =>
        {
            repository.Update(contract);
            WriteAudit("Contract", contract.Id, EventType.UpdateDraft, before, contract);
        });
        return contract;
    }

    public void DeleteContract(Guid contractId)
    {
        var contract = repository.Query<Contract>(tenantContext.TenantId).SingleOrDefault(x => x.Id == contractId)
            ?? throw new DomainRuleException("Contract not found.");

        var hasTaskOrders = repository.Query<TaskOrder>(tenantContext.TenantId).Any(x => x.ContractId == contractId);
        if (hasTaskOrders)
        {
            throw new DomainRuleException("Cannot delete contract with existing task orders.");
        }

        var before = new { contract.IsDeleted, contract.DeletedAtUtc, contract.DeletedByUserId };
        contract.IsDeleted = true;
        contract.DeletedAtUtc = clock.UtcNow;
        contract.DeletedByUserId = tenantContext.UserId;
        transaction.Execute(() =>
        {
            repository.Update(contract);
            WriteAudit("Contract", contract.Id, EventType.Reject, before, contract, "Soft deleted");
        });
    }

    public ContractOptionYear AddOptionYear(Guid contractId, DateOnly startDate, DateOnly endDate)
    {
        if (endDate < startDate)
        {
            throw new DomainRuleException("Option year end date must be on or after start date.");
        }

        var contract = repository.Query<Contract>(tenantContext.TenantId).SingleOrDefault(x => x.Id == contractId)
            ?? throw new DomainRuleException("Contract not found.");

        var existingNumbers = repository.Query<ContractOptionYear>(tenantContext.TenantId)
            .Where(x => x.ContractId == contractId)
            .Select(x => x.OptionYearNumber)
            .ToList();
        var nextNumber = (existingNumbers.Count == 0 ? 0 : existingNumbers.Max()) + 1;

        var optionYear = new ContractOptionYear
        {
            TenantId = contract.TenantId,
            ContractId = contract.Id,
            OptionYearNumber = nextNumber,
            StartDate = startDate,
            EndDate = endDate
        };

        transaction.Execute(() =>
        {
            repository.Add(optionYear);
            WriteAudit("ContractOptionYear", optionYear.Id, EventType.Create, null, optionYear);
        });
        return optionYear;
    }

    public ContractOptionYear UpdateOptionYear(Guid optionYearId, DateOnly startDate, DateOnly endDate)
    {
        if (endDate < startDate)
        {
            throw new DomainRuleException("Option year end date must be on or after start date.");
        }

        var optionYear = repository.Query<ContractOptionYear>(tenantContext.TenantId).SingleOrDefault(x => x.Id == optionYearId)
            ?? throw new DomainRuleException("Option year not found.");

        var before = new { optionYear.StartDate, optionYear.EndDate };
        optionYear.StartDate = startDate;
        optionYear.EndDate = endDate;
        transaction.Execute(() =>
        {
            repository.Update(optionYear);
            WriteAudit("ContractOptionYear", optionYear.Id, EventType.UpdateDraft, before, optionYear);
        });
        return optionYear;
    }

    public void DeleteOptionYear(Guid optionYearId)
    {
        var optionYear = repository.Query<ContractOptionYear>(tenantContext.TenantId).SingleOrDefault(x => x.Id == optionYearId)
            ?? throw new DomainRuleException("Option year not found.");
        var before = new { optionYear.IsDeleted, optionYear.DeletedAtUtc, optionYear.DeletedByUserId };
        optionYear.IsDeleted = true;
        optionYear.DeletedAtUtc = clock.UtcNow;
        optionYear.DeletedByUserId = tenantContext.UserId;
        transaction.Execute(() =>
        {
            repository.Update(optionYear);
            WriteAudit("ContractOptionYear", optionYear.Id, EventType.Reject, before, optionYear, "Soft deleted");
        });
    }

    public ContractPricing AddContractPricing(
        Guid contractId,
        string laborCategory,
        LaborSite site,
        decimal baseHourlyRate,
        decimal escalationPercent,
        decimal feePercent,
        DateOnly effectiveStart,
        DateOnly effectiveEnd)
    {
        if (effectiveEnd < effectiveStart)
        {
            throw new DomainRuleException("Pricing end date must be on or after start date.");
        }

        var contract = repository.Query<Contract>(tenantContext.TenantId).SingleOrDefault(x => x.Id == contractId)
            ?? throw new DomainRuleException("Contract not found.");

        var pricing = new ContractPricing
        {
            TenantId = contract.TenantId,
            ContractId = contract.Id,
            LaborCategory = laborCategory,
            Site = site,
            BaseHourlyRate = baseHourlyRate,
            EscalationPercent = escalationPercent,
            FeePercent = feePercent,
            EffectiveStartDate = effectiveStart,
            EffectiveEndDate = effectiveEnd
        };

        transaction.Execute(() =>
        {
            repository.Add(pricing);
            WriteAudit("ContractPricing", pricing.Id, EventType.ContractPricingChange, null, pricing);
        });
        return pricing;
    }

    public TaskOrder CreateTaskOrder(Guid contractId, string number, decimal budget, bool? requiresClinTracking = null)
    {
        var contract = repository.Query<Contract>(tenantContext.TenantId).SingleOrDefault(x => x.Id == contractId)
            ?? throw new DomainRuleException("Contract not found.");

        var taskOrder = new TaskOrder
        {
            TenantId = contract.TenantId,
            ContractId = contract.Id,
            Number = number,
            BudgetAmount = budget,
            RequiresClinTracking = requiresClinTracking ?? contract.RequiresClinTracking
        };
        transaction.Execute(() =>
        {
            repository.Add(taskOrder);
            WriteAudit("TaskOrder", taskOrder.Id, EventType.Create, null, taskOrder);
        });
        return taskOrder;
    }

    public TaskOrder UpdateTaskOrder(Guid taskOrderId, string number, decimal budget, bool? requiresClinTracking = null)
    {
        var taskOrder = repository.Query<TaskOrder>(tenantContext.TenantId).SingleOrDefault(x => x.Id == taskOrderId)
            ?? throw new DomainRuleException("Task order not found.");

        var before = new { taskOrder.Number, taskOrder.BudgetAmount, taskOrder.RequiresClinTracking };
        taskOrder.Number = number;
        taskOrder.BudgetAmount = budget;
        if (requiresClinTracking.HasValue)
        {
            taskOrder.RequiresClinTracking = requiresClinTracking.Value;
        }
        transaction.Execute(() =>
        {
            repository.Update(taskOrder);
            WriteAudit("TaskOrder", taskOrder.Id, EventType.UpdateDraft, before, taskOrder);
        });
        return taskOrder;
    }

    public void DeleteTaskOrder(Guid taskOrderId)
    {
        var taskOrder = repository.Query<TaskOrder>(tenantContext.TenantId).SingleOrDefault(x => x.Id == taskOrderId)
            ?? throw new DomainRuleException("Task order not found.");

        var hasClins = repository.Query<Clin>(tenantContext.TenantId).Any(x => x.TaskOrderId == taskOrderId);
        if (hasClins)
        {
            throw new DomainRuleException("Cannot delete task order with existing CLINs.");
        }

        var before = new { taskOrder.IsDeleted, taskOrder.DeletedAtUtc, taskOrder.DeletedByUserId };
        taskOrder.IsDeleted = true;
        taskOrder.DeletedAtUtc = clock.UtcNow;
        taskOrder.DeletedByUserId = tenantContext.UserId;
        transaction.Execute(() =>
        {
            repository.Update(taskOrder);
            WriteAudit("TaskOrder", taskOrder.Id, EventType.Reject, before, taskOrder, "Soft deleted");
        });
    }

    public Clin CreateClin(Guid taskOrderId, string number)
    {
        var taskOrder = repository.Query<TaskOrder>(tenantContext.TenantId).SingleOrDefault(x => x.Id == taskOrderId)
            ?? throw new DomainRuleException("Task order not found.");

        var clin = new Clin { TenantId = taskOrder.TenantId, TaskOrderId = taskOrder.Id, Number = number };
        transaction.Execute(() =>
        {
            repository.Add(clin);
            WriteAudit("Clin", clin.Id, EventType.Create, null, clin);
        });
        return clin;
    }

    public Clin UpdateClin(Guid clinId, string number)
    {
        var clin = repository.Query<Clin>(tenantContext.TenantId).SingleOrDefault(x => x.Id == clinId)
            ?? throw new DomainRuleException("CLIN not found.");

        var before = new { clin.Number };
        clin.Number = number;
        transaction.Execute(() =>
        {
            repository.Update(clin);
            WriteAudit("Clin", clin.Id, EventType.UpdateDraft, before, clin);
        });
        return clin;
    }

    public void DeleteClin(Guid clinId)
    {
        var clin = repository.Query<Clin>(tenantContext.TenantId).SingleOrDefault(x => x.Id == clinId)
            ?? throw new DomainRuleException("CLIN not found.");

        var hasWbs = repository.Query<WbsNode>(tenantContext.TenantId).Any(x => x.ClinId == clinId);
        if (hasWbs)
        {
            throw new DomainRuleException("Cannot delete CLIN with existing WBS nodes.");
        }

        var before = new { clin.IsDeleted, clin.DeletedAtUtc, clin.DeletedByUserId };
        clin.IsDeleted = true;
        clin.DeletedAtUtc = clock.UtcNow;
        clin.DeletedByUserId = tenantContext.UserId;
        transaction.Execute(() =>
        {
            repository.Update(clin);
            WriteAudit("Clin", clin.Id, EventType.Reject, before, clin, "Soft deleted");
        });
    }

    public WbsNode CreateWbs(Guid clinId, string code, Guid? parentWbsNodeId)
    {
        var clin = repository.Query<Clin>(tenantContext.TenantId).SingleOrDefault(x => x.Id == clinId)
            ?? throw new DomainRuleException("CLIN not found.");

        var wbs = new WbsNode { TenantId = clin.TenantId, ClinId = clin.Id, Code = code, ParentWbsNodeId = parentWbsNodeId };
        transaction.Execute(() =>
        {
            repository.Add(wbs);
            WriteAudit("WbsNode", wbs.Id, EventType.Create, null, wbs);
        });
        return wbs;
    }

    public WbsNode UpdateWbs(Guid wbsId, string code, Guid? parentWbsNodeId)
    {
        var wbs = repository.Query<WbsNode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == wbsId)
            ?? throw new DomainRuleException("WBS not found.");

        if (parentWbsNodeId == wbsId)
        {
            throw new DomainRuleException("WBS node cannot parent itself.");
        }

        var before = new { wbs.Code, wbs.ParentWbsNodeId };
        wbs.Code = code;
        wbs.ParentWbsNodeId = parentWbsNodeId;
        transaction.Execute(() =>
        {
            repository.Update(wbs);
            WriteAudit("WbsNode", wbs.Id, EventType.UpdateDraft, before, wbs);
        });
        return wbs;
    }

    public void DeleteWbs(Guid wbsId)
    {
        var wbs = repository.Query<WbsNode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == wbsId)
            ?? throw new DomainRuleException("WBS not found.");

        var hasChildWbs = repository.Query<WbsNode>(tenantContext.TenantId).Any(x => x.ParentWbsNodeId == wbsId);
        if (hasChildWbs)
        {
            throw new DomainRuleException("Cannot delete WBS node with child nodes.");
        }

        var hasChargeCodes = repository.Query<ChargeCode>(tenantContext.TenantId).Any(x => x.WbsNodeId == wbsId);
        if (hasChargeCodes)
        {
            throw new DomainRuleException("Cannot delete WBS node with existing charge codes.");
        }

        var before = new { wbs.IsDeleted, wbs.DeletedAtUtc, wbs.DeletedByUserId };
        wbs.IsDeleted = true;
        wbs.DeletedAtUtc = clock.UtcNow;
        wbs.DeletedByUserId = tenantContext.UserId;
        transaction.Execute(() =>
        {
            repository.Update(wbs);
            WriteAudit("WbsNode", wbs.Id, EventType.Reject, before, wbs, "Soft deleted");
        });
    }

    public ChargeCode CreateChargeCode(Guid wbsId, string code, CostType costType)
    {
        var wbs = repository.Query<WbsNode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == wbsId)
            ?? throw new DomainRuleException("WBS not found.");

        var chargeCode = new ChargeCode
        {
            TenantId = wbs.TenantId,
            WbsNodeId = wbs.Id,
            Code = code,
            CostType = costType,
            IsActive = true
        };
        transaction.Execute(() =>
        {
            repository.Add(chargeCode);
            WriteAudit("ChargeCode", chargeCode.Id, EventType.Create, null, chargeCode);
        });
        return chargeCode;
    }

    public ChargeCode UpdateChargeCode(Guid chargeCodeId, string code, CostType costType)
    {
        var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == chargeCodeId)
            ?? throw new DomainRuleException("Charge code not found.");

        var before = new { chargeCode.Code, chargeCode.CostType };
        chargeCode.Code = code;
        chargeCode.CostType = costType;
        transaction.Execute(() =>
        {
            repository.Update(chargeCode);
            WriteAudit("ChargeCode", chargeCode.Id, EventType.UpdateDraft, before, chargeCode);
        });
        return chargeCode;
    }

    public void DeleteChargeCode(Guid chargeCodeId)
    {
        var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == chargeCodeId)
            ?? throw new DomainRuleException("Charge code not found.");

        var hasAssignments = repository.Query<Assignment>(tenantContext.TenantId).Any(x => x.ChargeCodeId == chargeCodeId);
        if (hasAssignments)
        {
            throw new DomainRuleException("Cannot delete charge code with assignments.");
        }

        var hasTimesheetLines = repository.Query<TimesheetLine>(tenantContext.TenantId).Any(x => x.ChargeCodeId == chargeCodeId);
        if (hasTimesheetLines)
        {
            throw new DomainRuleException("Cannot delete charge code with charged time.");
        }

        var before = new { chargeCode.IsDeleted, chargeCode.IsActive, chargeCode.DeletedAtUtc, chargeCode.DeletedByUserId };
        chargeCode.IsDeleted = true;
        chargeCode.IsActive = false;
        chargeCode.DeletedAtUtc = clock.UtcNow;
        chargeCode.DeletedByUserId = tenantContext.UserId;
        transaction.Execute(() =>
        {
            repository.Update(chargeCode);
            WriteAudit("ChargeCode", chargeCode.Id, EventType.Reject, before, chargeCode, "Soft deleted");
        });
    }

    public void SetChargeCodeActive(Guid chargeCodeId, bool isActive, string reason)
    {
        var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == chargeCodeId)
            ?? throw new DomainRuleException("Charge code not found.");

        var before = new { chargeCode.Id, chargeCode.IsActive };
        chargeCode.IsActive = isActive;
        transaction.Execute(() =>
        {
            repository.Update(chargeCode);
            WriteAudit("ChargeCode", chargeCode.Id, EventType.ChargeCodeLifecycleChange, before, chargeCode, reason);
        });
    }

    public Assignment AssignUserToChargeCode(Guid userId, Guid chargeCodeId, DateOnly start, DateOnly end, bool supervisorOverrideAllowed)
    {
        if (end < start)
        {
            throw new DomainRuleException("Assignment end date must be on or after start date.");
        }

        var chargeCode = repository.Query<ChargeCode>(tenantContext.TenantId).SingleOrDefault(x => x.Id == chargeCodeId)
            ?? throw new DomainRuleException("Charge code not found.");

        var user = repository.Query<AppUser>(tenantContext.TenantId).SingleOrDefault(x => x.Id == userId)
            ?? throw new DomainRuleException("User not found.");

        var assignment = new Assignment
        {
            TenantId = tenantContext.TenantId,
            UserId = user.Id,
            ChargeCodeId = chargeCode.Id,
            EffectiveStartDate = start,
            EffectiveEndDate = end,
            SupervisorOverrideAllowed = supervisorOverrideAllowed
        };

        transaction.Execute(() =>
        {
            repository.Add(assignment);
            WriteAudit("Assignment", assignment.Id, EventType.AssignmentChange, null, assignment);
        });
        return assignment;
    }

    public TimeChargeOverrideApproval ApproveOutOfWindowCharge(Guid userId, Guid chargeCodeId, DateOnly workDate, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Supervisor override reason is required.");
        }

        var approval = new TimeChargeOverrideApproval
        {
            TenantId = tenantContext.TenantId,
            UserId = userId,
            ChargeCodeId = chargeCodeId,
            WorkDate = workDate,
            ApprovedByUserId = tenantContext.UserId,
            Reason = reason,
            ApprovedAtUtc = clock.UtcNow
        };

        transaction.Execute(() =>
        {
            repository.Add(approval);
            WriteAudit("TimeChargeOverrideApproval", approval.Id, EventType.OverrideApproval, null, approval, reason);
            _notifications?.SendToUser(
                userId,
                "Out-of-Window Charge Approved",
                $"Your supervisor approved an out-of-window charge for {workDate} on charge code {chargeCodeId}. Reason: {reason}",
                "OverrideApproval");
        });
        return approval;
    }

    public OvertimeAllowanceApproval ApproveOvertimeAllowance(Guid userId, DateOnly workDate, int overtimeMinutes, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Overtime approval reason is required.");
        }

        if (overtimeMinutes <= 0)
        {
            throw new DomainRuleException("Approved overtime minutes must be greater than zero.");
        }

        var profile = repository.Query<PersonnelProfile>(tenantContext.TenantId).SingleOrDefault(x => x.UserId == userId)
            ?? throw new DomainRuleException("Personnel profile missing for employee.");
        if (profile.SupervisorUserId != tenantContext.UserId)
        {
            throw new DomainRuleException("Supervisor is not assigned to approve overtime for this employee.");
        }

        var approval = new OvertimeAllowanceApproval
        {
            TenantId = tenantContext.TenantId,
            UserId = userId,
            WorkDate = workDate,
            ApprovedOvertimeMinutes = overtimeMinutes,
            ApprovedByUserId = tenantContext.UserId,
            Reason = reason.Trim(),
            ApprovedAtUtc = clock.UtcNow
        };

        transaction.Execute(() =>
        {
            repository.Add(approval);
            WriteAudit("OvertimeAllowanceApproval", approval.Id, EventType.OvertimeApproval, null, approval, reason);
            _notifications?.SendToUser(
                userId,
                "Overtime Approved",
                $"Your supervisor approved {overtimeMinutes} overtime minute(s) for {workDate:yyyy-MM-dd}. Reason: {reason}",
                "OvertimeApproval");
        });

        return approval;
    }

    public FuturePtoApproval ApproveFuturePto(Guid userId, DateOnly workDate, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainRuleException("Future PTO approval reason is required.");
        }

        var today = DateOnly.FromDateTime(clock.UtcNow.Date);
        if (workDate <= today)
        {
            throw new DomainRuleException("Future PTO approval is only valid for future dates.");
        }

        var profile = repository.Query<PersonnelProfile>(tenantContext.TenantId).SingleOrDefault(x => x.UserId == userId)
            ?? throw new DomainRuleException("Personnel profile missing for employee.");
        if (profile.SupervisorUserId != tenantContext.UserId)
        {
            throw new DomainRuleException("Supervisor is not assigned to approve PTO for this employee.");
        }

        var approval = new FuturePtoApproval
        {
            TenantId = tenantContext.TenantId,
            UserId = userId,
            WorkDate = workDate,
            ApprovedByUserId = tenantContext.UserId,
            Reason = reason.Trim(),
            ApprovedAtUtc = clock.UtcNow
        };

        transaction.Execute(() =>
        {
            repository.Add(approval);
            WriteAudit("FuturePtoApproval", approval.Id, EventType.FuturePtoApproval, null, approval, reason);
            _notifications?.SendToUser(
                userId,
                "Future PTO Approved",
                $"Your supervisor approved future PTO for {workDate:yyyy-MM-dd}. Reason: {reason}",
                "FuturePtoApproval");
        });

        return approval;
    }

    public void SetSupervisor(Guid employeeUserId, Guid supervisorUserId)
    {
        var profile = repository.Query<PersonnelProfile>(tenantContext.TenantId).SingleOrDefault(x => x.UserId == employeeUserId)
            ?? throw new DomainRuleException("Personnel profile not found.");

        var before = new { profile.UserId, profile.SupervisorUserId };
        profile.SupervisorUserId = supervisorUserId;
        transaction.Execute(() =>
        {
            repository.Update(profile);
            WriteAudit("PersonnelProfile", profile.Id, EventType.SupervisorRelationshipChange, before, profile);
        });
    }

    public AccountingPeriod CreateAccountingPeriod(DateOnly startDate, DateOnly endDate)
    {
        if (endDate < startDate)
        {
            throw new DomainRuleException("Accounting period end date must be on or after start date.");
        }

        var period = new AccountingPeriod
        {
            TenantId = tenantContext.TenantId,
            StartDate = startDate,
            EndDate = endDate,
            Status = AccountingPeriodStatus.Open
        };

        transaction.Execute(() =>
        {
            repository.Add(period);
            WriteAudit("AccountingPeriod", period.Id, EventType.Create, null, period);
        });
        return period;
    }

    public void SetAccountingPeriodStatus(Guid periodId, AccountingPeriodStatus status, string reason)
    {
        var period = repository.Query<AccountingPeriod>(tenantContext.TenantId).SingleOrDefault(x => x.Id == periodId)
            ?? throw new DomainRuleException("Accounting period not found.");

        var before = new { period.Id, period.Status };
        period.Status = status;
        transaction.Execute(() =>
        {
            repository.Update(period);
            WriteAudit("AccountingPeriod", period.Id, EventType.AccountingPeriodChange, before, period, reason);
        });
    }

    public AllowabilityRule UpsertAllowabilityRule(CostType costType, string ruleName, string description, bool requiresComment)
    {
        var existing = repository.Query<AllowabilityRule>(tenantContext.TenantId).SingleOrDefault(x => x.CostType == costType && x.RuleName == ruleName);

        if (existing is null)
        {
            var created = new AllowabilityRule
            {
                TenantId = tenantContext.TenantId,
                CostType = costType,
                RuleName = ruleName,
                RuleDescription = description,
                RequiresComment = requiresComment
            };

            transaction.Execute(() =>
            {
                repository.Add(created);
                WriteAudit("AllowabilityRule", created.Id, EventType.AllowabilityRuleChange, null, created);
            });
            return created;
        }

        var before = new
        {
            existing.CostType,
            existing.RuleName,
            existing.RuleDescription,
            existing.RequiresComment
        };

        existing.RuleDescription = description;
        existing.RequiresComment = requiresComment;
        transaction.Execute(() =>
        {
            repository.Update(existing);
            WriteAudit("AllowabilityRule", existing.Id, EventType.AllowabilityRuleChange, before, existing);
        });
        return existing;
    }

    public IReadOnlyList<AuditEvent> ForensicAuditReport(string? entityType = null)
    {
        var query = repository.Query<AuditEvent>(tenantContext.TenantId);
        if (!string.IsNullOrWhiteSpace(entityType))
        {
            var normalizedEntityType = entityType.Trim().ToUpperInvariant();
            query = query.Where(x => x.EntityType.ToUpper() == normalizedEntityType);
        }

        return query.OrderByDescending(x => x.OccurredAtUtc).ToList();
    }

    private void WriteAudit(string entityType, Guid entityId, EventType eventType, object? before, object? after, string? reason = null)
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
