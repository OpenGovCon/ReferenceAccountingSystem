using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using GovConMoney.Infrastructure.Persistence;

namespace GovConMoney.Infrastructure;

public static class SeedData
{
    public static SeedContext Initialize(InMemoryDataStore store)
    {
        if (store.Tenants.Any())
        {
            var existingTenant = store.Tenants.First();
            return BuildContext(store, existingTenant.Id);
        }

        var tenantId = Guid.NewGuid();
        var tenant = new Tenant { Id = tenantId, Name = "Apex Gov Services" };
        store.Tenants.Add(tenant);
        store.WorkPeriodConfigurations.Add(new WorkPeriodConfiguration
        {
            TenantId = tenantId,
            WeekStartDay = (int)DayOfWeek.Monday,
            PeriodLengthDays = 7,
            DailyEntryRequired = true,
            DailyEntryGraceDays = 1,
            DailyEntryHardFail = true,
            DailyEntryIncludeWeekends = false,
            UpdatedAtUtc = DateTime.UtcNow
        });
        store.ManagementReviewPolicies.Add(new ManagementReviewPolicy
        {
            TenantId = tenantId,
            RequireManagerApprovalForBillingAboveThreshold = true,
            BillingManagerApprovalThreshold = 50000m,
            RequireManagerCoSignForAdjustingAboveThreshold = true,
            AdjustingManagerCoSignThreshold = 10000m,
            EnablePeriodicInternalAuditAttestation = true,
            InternalAuditCadenceDays = 30,
            InternalAuditDueDaysAfterPeriodEnd = 10,
            RequireManagerInternalAuditAttestation = true,
            RequireComplianceInternalAuditAttestation = true,
            UpdatedAtUtc = DateTime.UtcNow
        });

        var admin = AddUser(store, tenantId, "admin", "Admin", "EMP-1000");
        var compliance = AddUser(store, tenantId, "compliance", "Compliance", "EMP-1001");
        var accountant = AddUser(store, tenantId, "accountant", "Accountant", "EMP-1002");
        var supervisor = AddUser(store, tenantId, "supervisor", "Supervisor", "EMP-1003");
        var timeReporter = AddUser(store, tenantId, "timereporter", "TimeReporter", "EMP-1004");
        var manager = AddUser(store, tenantId, "manager", "Manager", "EMP-1005");

        store.PersonnelProfiles.Add(new PersonnelProfile { TenantId = tenantId, UserId = supervisor.Id, HourlyRate = 85m });
        store.PersonnelProfiles.Add(new PersonnelProfile { TenantId = tenantId, UserId = timeReporter.Id, SupervisorUserId = supervisor.Id, HourlyRate = 55m });

        var contract = new Contract
        {
            TenantId = tenantId,
            ContractNumber = "W15QKN-26-C-1000",
            Name = "Modernization",
            BudgetAmount = 5_000_000m,
            ContractType = ContractType.CostPlusFee,
            BaseYearStartDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddMonths(-1)),
            BaseYearEndDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddMonths(11))
        };
        var taskOrder = new TaskOrder { TenantId = tenantId, ContractId = contract.Id, Number = "TO-01", BudgetAmount = 1_200_000m };
        var clin = new Clin { TenantId = tenantId, TaskOrderId = taskOrder.Id, Number = "0001AA" };
        var wbs = new WbsNode { TenantId = tenantId, ClinId = clin.Id, Code = "1.1" };
        var chargeCode = new ChargeCode { TenantId = tenantId, WbsNodeId = wbs.Id, Code = "DEV-001", CostType = CostType.Direct, IsActive = true };

        store.Contracts.Add(contract);
        store.ContractOptionYears.Add(new ContractOptionYear
        {
            TenantId = tenantId,
            ContractId = contract.Id,
            OptionYearNumber = 1,
            StartDate = contract.BaseYearEndDate.AddDays(1),
            EndDate = contract.BaseYearEndDate.AddYears(1)
        });
        store.ContractPricings.Add(new ContractPricing
        {
            TenantId = tenantId,
            ContractId = contract.Id,
            LaborCategory = "Software Engineer III",
            Site = LaborSite.GovernmentSite,
            BaseHourlyRate = 165m,
            EscalationPercent = 3.0m,
            FeePercent = 8.5m,
            EffectiveStartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddMonths(-1)),
            EffectiveEndDate = DateOnly.FromDateTime(DateTime.UtcNow.AddYears(1))
        });
        store.TaskOrders.Add(taskOrder);
        store.Clins.Add(clin);
        store.WbsNodes.Add(wbs);
        store.ChargeCodes.Add(chargeCode);

        store.AllowabilityRules.Add(new AllowabilityRule
        {
            TenantId = tenantId,
            CostType = CostType.Unallowable,
            RuleName = "Unallowable requires comment",
            RuleDescription = "Unallowable time must include compliance note for billing exclusion.",
            RequiresComment = true
        });

        store.Assignments.Add(new Assignment
        {
            TenantId = tenantId,
            UserId = timeReporter.Id,
            ChargeCodeId = chargeCode.Id,
            EffectiveStartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-30)),
            EffectiveEndDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(365)),
            SupervisorOverrideAllowed = true
        });

        store.AccountingPeriods.Add(new AccountingPeriod
        {
            TenantId = tenantId,
            StartDate = new DateOnly(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1),
            EndDate = new DateOnly(DateTime.UtcNow.Year, DateTime.UtcNow.Month, DateTime.DaysInMonth(DateTime.UtcNow.Year, DateTime.UtcNow.Month)),
            Status = AccountingPeriodStatus.Open
        });

        store.AiPrompts.Add(new AiPrompt
        {
            TenantId = tenantId,
            Function = "AccountantReporting",
            Prompt = "Show contract burndown and budget variance by task order for the current period."
        });

        store.ExternalServiceConfigs.Add(new ExternalServiceConfig
        {
            TenantId = tenantId,
            ServiceName = "OpenAI",
            Endpoint = "https://api.openai.com",
            ApiKeyMasked = "***"
        });

        var overheadPool = new IndirectPool
        {
            TenantId = tenantId,
            Name = "Overhead Pool",
            EffectiveStartDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddYears(-1)),
            EffectiveEndDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddYears(1)),
            PoolCostType = CostType.Indirect,
            BaseCostType = CostType.Direct,
            ExcludeUnallowable = true,
            IsActive = true
        };
        store.IndirectPools.Add(overheadPool);
        store.AllocationBases.Add(new AllocationBase
        {
            TenantId = tenantId,
            IndirectPoolId = overheadPool.Id,
            Name = "Direct Labor Dollars",
            BaseCostType = CostType.Direct,
            BaseMethod = AllocationBaseMethod.DirectLaborDollars,
            IsActive = true
        });

        AddPayrollTemplateProfiles(store, tenantId, accountant.Id);

        store.SaveChanges();
        return new SeedContext(tenantId, admin.Id, compliance.Id, accountant.Id, supervisor.Id, timeReporter.Id, manager.Id, contract.Id, taskOrder.Id, chargeCode.Id);
    }

    private static AppUser AddUser(InMemoryDataStore store, Guid tenantId, string username, string role, string employeeExternalId)
    {
        var user = new AppUser
        {
            TenantId = tenantId,
            UserName = username,
            Email = $"{username}@example.govcon",
            EmployeeExternalId = employeeExternalId,
            MfaEnabled = false,
            PasskeyRequired = false
        };

        user.Roles.Add(role);
        store.Users.Add(user);
        return user;
    }

    private static SeedContext BuildContext(InMemoryDataStore store, Guid tenantId)
    {
        var changed = false;
        var users = store.Users.Where(x => x.TenantId == tenantId).ToList();

        if (!store.WorkPeriodConfigurations.Any(x => x.TenantId == tenantId))
        {
            store.WorkPeriodConfigurations.Add(new WorkPeriodConfiguration
            {
                TenantId = tenantId,
                WeekStartDay = (int)DayOfWeek.Monday,
                PeriodLengthDays = 7,
                DailyEntryRequired = true,
                DailyEntryGraceDays = 1,
                DailyEntryHardFail = true,
                DailyEntryIncludeWeekends = false,
                UpdatedAtUtc = DateTime.UtcNow
            });
            changed = true;
        }
        if (!store.ManagementReviewPolicies.Any(x => x.TenantId == tenantId))
        {
            store.ManagementReviewPolicies.Add(new ManagementReviewPolicy
            {
                TenantId = tenantId,
                RequireManagerApprovalForBillingAboveThreshold = true,
                BillingManagerApprovalThreshold = 50000m,
                RequireManagerCoSignForAdjustingAboveThreshold = true,
                AdjustingManagerCoSignThreshold = 10000m,
                EnablePeriodicInternalAuditAttestation = true,
                InternalAuditCadenceDays = 30,
                InternalAuditDueDaysAfterPeriodEnd = 10,
                RequireManagerInternalAuditAttestation = true,
                RequireComplianceInternalAuditAttestation = true,
                UpdatedAtUtc = DateTime.UtcNow
            });
            changed = true;
        }
        else
        {
            var config = store.WorkPeriodConfigurations.First(x => x.TenantId == tenantId);
            if (config.DailyEntryGraceDays < 0)
            {
                config.DailyEntryGraceDays = 1;
                changed = true;
            }
        }

        AppUser EnsureUser(string role, string username)
        {
            var user = users.SingleOrDefault(x => x.Roles.Contains(role))
                ?? users.SingleOrDefault(x => x.UserName.ToUpper() == username.ToUpper());
            if (user is null)
            {
                user = AddUser(store, tenantId, username, role, $"EMP-{Math.Abs(username.GetHashCode()) % 100000:D5}");
                users.Add(user);
                changed = true;
                return user;
            }

            if (!user.Roles.Contains(role))
            {
                user.Roles.Add(role);
                changed = true;
            }

            if (string.IsNullOrWhiteSpace(user.EmployeeExternalId))
            {
                user.EmployeeExternalId = $"EMP-{Math.Abs(user.UserName.GetHashCode()) % 100000:D5}";
                changed = true;
            }

            return user;
        }

        var admin = EnsureUser("Admin", "admin");
        var compliance = EnsureUser("Compliance", "compliance");
        var accountant = EnsureUser("Accountant", "accountant");
        var supervisor = EnsureUser("Supervisor", "supervisor");
        var reporter = EnsureUser("TimeReporter", "timereporter");
        var manager = EnsureUser("Manager", "manager");

        if (!store.PersonnelProfiles.Any(x => x.TenantId == tenantId && x.UserId == supervisor.Id))
        {
            store.PersonnelProfiles.Add(new PersonnelProfile { TenantId = tenantId, UserId = supervisor.Id, HourlyRate = 85m });
            changed = true;
        }
        if (!store.PersonnelProfiles.Any(x => x.TenantId == tenantId && x.UserId == reporter.Id))
        {
            store.PersonnelProfiles.Add(new PersonnelProfile { TenantId = tenantId, UserId = reporter.Id, SupervisorUserId = supervisor.Id, HourlyRate = 55m });
            changed = true;
        }

        var contract = store.Contracts.FirstOrDefault(x => x.TenantId == tenantId);
        if (contract is null)
        {
            contract = new Contract
            {
                TenantId = tenantId,
                ContractNumber = "W15QKN-26-C-1000",
                Name = "Modernization",
                BudgetAmount = 5_000_000m,
                ContractType = ContractType.CostPlusFee,
                BaseYearStartDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddMonths(-1)),
                BaseYearEndDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddMonths(11))
            };
            store.Contracts.Add(contract);
            changed = true;
        }

        if (!store.ContractOptionYears.Any(x => x.TenantId == tenantId && x.ContractId == contract.Id))
        {
            store.ContractOptionYears.Add(new ContractOptionYear
            {
                TenantId = tenantId,
                ContractId = contract.Id,
                OptionYearNumber = 1,
                StartDate = contract.BaseYearEndDate.AddDays(1),
                EndDate = contract.BaseYearEndDate.AddYears(1)
            });
            changed = true;
        }

        if (!store.ContractPricings.Any(x => x.TenantId == tenantId && x.ContractId == contract.Id))
        {
            store.ContractPricings.Add(new ContractPricing
            {
                TenantId = tenantId,
                ContractId = contract.Id,
                LaborCategory = "Software Engineer III",
                Site = LaborSite.GovernmentSite,
                BaseHourlyRate = 165m,
                EscalationPercent = 3.0m,
                FeePercent = 8.5m,
                EffectiveStartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddMonths(-1)),
                EffectiveEndDate = DateOnly.FromDateTime(DateTime.UtcNow.AddYears(1))
            });
            changed = true;
        }

        var taskOrder = store.TaskOrders.FirstOrDefault(x => x.TenantId == tenantId && x.ContractId == contract.Id);
        if (taskOrder is null)
        {
            taskOrder = new TaskOrder
            {
                TenantId = tenantId,
                ContractId = contract.Id,
                Number = "TO-01",
                BudgetAmount = 1_200_000m
            };
            store.TaskOrders.Add(taskOrder);
            changed = true;
        }

        var clin = store.Clins.FirstOrDefault(x => x.TenantId == tenantId && x.TaskOrderId == taskOrder.Id);
        if (clin is null)
        {
            clin = new Clin { TenantId = tenantId, TaskOrderId = taskOrder.Id, Number = "0001AA" };
            store.Clins.Add(clin);
            changed = true;
        }

        var wbs = store.WbsNodes.FirstOrDefault(x => x.TenantId == tenantId && x.ClinId == clin.Id);
        if (wbs is null)
        {
            wbs = new WbsNode { TenantId = tenantId, ClinId = clin.Id, Code = "1.1" };
            store.WbsNodes.Add(wbs);
            changed = true;
        }

        var chargeCode = store.ChargeCodes.FirstOrDefault(x => x.TenantId == tenantId && x.WbsNodeId == wbs.Id);
        if (chargeCode is null)
        {
            chargeCode = new ChargeCode { TenantId = tenantId, WbsNodeId = wbs.Id, Code = "DEV-001", CostType = CostType.Direct, IsActive = true };
            store.ChargeCodes.Add(chargeCode);
            changed = true;
        }

        if (!store.AllowabilityRules.Any(x => x.TenantId == tenantId))
        {
            store.AllowabilityRules.Add(new AllowabilityRule
            {
                TenantId = tenantId,
                CostType = CostType.Unallowable,
                RuleName = "Unallowable requires comment",
                RuleDescription = "Unallowable time must include compliance note for billing exclusion.",
                RequiresComment = true
            });
            changed = true;
        }

        if (!store.Assignments.Any(x => x.TenantId == tenantId && x.UserId == reporter.Id && x.ChargeCodeId == chargeCode.Id))
        {
            store.Assignments.Add(new Assignment
            {
                TenantId = tenantId,
                UserId = reporter.Id,
                ChargeCodeId = chargeCode.Id,
                EffectiveStartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-30)),
                EffectiveEndDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(365)),
                SupervisorOverrideAllowed = true
            });
            changed = true;
        }

        var monthStart = new DateOnly(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1);
        var monthEnd = new DateOnly(DateTime.UtcNow.Year, DateTime.UtcNow.Month, DateTime.DaysInMonth(DateTime.UtcNow.Year, DateTime.UtcNow.Month));
        if (!store.AccountingPeriods.Any(x => x.TenantId == tenantId && x.StartDate == monthStart && x.EndDate == monthEnd))
        {
            store.AccountingPeriods.Add(new AccountingPeriod
            {
                TenantId = tenantId,
                StartDate = monthStart,
                EndDate = monthEnd,
                Status = AccountingPeriodStatus.Open
            });
            changed = true;
        }

        if (!store.AiPrompts.Any(x => x.TenantId == tenantId && x.Function == "AccountantReporting"))
        {
            store.AiPrompts.Add(new AiPrompt
            {
                TenantId = tenantId,
                Function = "AccountantReporting",
                Prompt = "Show contract burndown and budget variance by task order for the current period."
            });
            changed = true;
        }

        if (!store.ExternalServiceConfigs.Any(x => x.TenantId == tenantId && x.ServiceName == "OpenAI"))
        {
            store.ExternalServiceConfigs.Add(new ExternalServiceConfig
            {
                TenantId = tenantId,
                ServiceName = "OpenAI",
                Endpoint = "https://api.openai.com",
                ApiKeyMasked = "***"
            });
            changed = true;
        }

        if (!store.IndirectPools.Any(x => x.TenantId == tenantId))
        {
            var overheadPool = new IndirectPool
            {
                TenantId = tenantId,
                Name = "Overhead Pool",
                EffectiveStartDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddYears(-1)),
                EffectiveEndDate = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddYears(1)),
                PoolCostType = CostType.Indirect,
                BaseCostType = CostType.Direct,
                ExcludeUnallowable = true,
                IsActive = true
            };
            store.IndirectPools.Add(overheadPool);
            store.AllocationBases.Add(new AllocationBase
            {
                TenantId = tenantId,
                IndirectPoolId = overheadPool.Id,
                Name = "Direct Labor Dollars",
                BaseCostType = CostType.Direct,
                BaseMethod = AllocationBaseMethod.DirectLaborDollars,
                IsActive = true
            });
            changed = true;
        }

        changed |= AddPayrollTemplateProfiles(store, tenantId, accountant.Id);

        if (changed)
        {
            store.SaveChanges();
        }

        return new SeedContext(tenantId, admin.Id, compliance.Id, accountant.Id, supervisor.Id, reporter.Id, manager.Id, contract.Id, taskOrder.Id, chargeCode.Id);
    }

    private static bool AddPayrollTemplateProfiles(InMemoryDataStore store, Guid tenantId, Guid updatedByUserId)
    {
        var changed = false;
        changed |= EnsurePayrollProfile(store, tenantId, updatedByUserId,
            "Default Payroll CSV", "PayrollExtract", ",", true,
            "EmployeeId", "Labor", "Fringe", "Tax", "Other", "Notes",
            "EmployeeId,Labor,Fringe,Tax,Other",
            requireKnownEmployeeExternalId: true,
            disallowDuplicateEmployeeExternalIds: true,
            requirePositiveLaborAmount: true);
        changed |= EnsurePayrollProfile(store, tenantId, updatedByUserId,
            "ADP WorkforceNow (Example)", "ADP", ",", true,
            "EmployeeID", "RegularEarnings", "EmployerBenefits", "EmployerTaxes", "OtherEarnings", "Memo",
            "EmployeeID,RegularEarnings,EmployerTaxes",
            requireKnownEmployeeExternalId: true,
            disallowDuplicateEmployeeExternalIds: true,
            requirePositiveLaborAmount: true);
        changed |= EnsurePayrollProfile(store, tenantId, updatedByUserId,
            "Paychex Flex (Example)", "Paychex", ",", true,
            "EmpID", "GrossWages", "Benefits", "PayrollTaxes", "OtherComp", "Notes",
            "EmpID,GrossWages,PayrollTaxes",
            requireKnownEmployeeExternalId: true,
            disallowDuplicateEmployeeExternalIds: true,
            requirePositiveLaborAmount: true);
        changed |= EnsurePayrollProfile(store, tenantId, updatedByUserId,
            "QuickBooks Payroll (Example)", "QuickBooks", ",", true,
            "Employee", "RegularPay", "Benefits", "PayrollTax", "OtherPayrollCost", "Memo",
            "Employee,RegularPay,PayrollTax",
            requireKnownEmployeeExternalId: true,
            disallowDuplicateEmployeeExternalIds: true,
            requirePositiveLaborAmount: true);
        return changed;
    }

    private static bool EnsurePayrollProfile(
        InMemoryDataStore store,
        Guid tenantId,
        Guid updatedByUserId,
        string name,
        string sourceSystem,
        string delimiter,
        bool hasHeaderRow,
        string employeeExternalIdColumn,
        string laborAmountColumn,
        string fringeAmountColumn,
        string taxAmountColumn,
        string otherAmountColumn,
        string? notesColumn,
        string? requiredHeadersCsv,
        bool requireKnownEmployeeExternalId,
        bool disallowDuplicateEmployeeExternalIds,
        bool requirePositiveLaborAmount)
    {
        if (store.PayrollImportProfiles.Any(x => x.TenantId == tenantId && x.Name == name))
        {
            return false;
        }

        store.PayrollImportProfiles.Add(new PayrollImportProfile
        {
            TenantId = tenantId,
            Name = name,
            SourceSystem = sourceSystem,
            Delimiter = delimiter,
            HasHeaderRow = hasHeaderRow,
            EmployeeExternalIdColumn = employeeExternalIdColumn,
            LaborAmountColumn = laborAmountColumn,
            FringeAmountColumn = fringeAmountColumn,
            TaxAmountColumn = taxAmountColumn,
            OtherAmountColumn = otherAmountColumn,
            NotesColumn = notesColumn,
            RequiredHeadersCsv = requiredHeadersCsv,
            RequireKnownEmployeeExternalId = requireKnownEmployeeExternalId,
            DisallowDuplicateEmployeeExternalIds = disallowDuplicateEmployeeExternalIds,
            RequirePositiveLaborAmount = requirePositiveLaborAmount,
            IsActive = true,
            UpdatedAtUtc = DateTime.UtcNow,
            UpdatedByUserId = updatedByUserId
        });
        return true;
    }
}

public sealed record SeedContext(
    Guid TenantId,
    Guid AdminUserId,
    Guid ComplianceUserId,
    Guid AccountantUserId,
    Guid SupervisorUserId,
    Guid TimeReporterUserId,
    Guid ManagerUserId,
    Guid ContractId,
    Guid TaskOrderId,
    Guid ChargeCodeId);
