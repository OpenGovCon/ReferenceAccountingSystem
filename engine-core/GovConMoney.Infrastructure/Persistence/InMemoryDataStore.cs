using GovConMoney.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace GovConMoney.Infrastructure.Persistence;

public class InMemoryDataStore(GovConMoneyDbContext db)
{
    public Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade Database => db.Database;

    public DbSet<Tenant> Tenants => db.Tenants;
    public DbSet<UserNotification> UserNotifications => db.UserNotifications;
    public DbSet<UserNotificationState> UserNotificationStates => db.UserNotificationStates;
    public DbSet<WorkPeriodConfiguration> WorkPeriodConfigurations => db.WorkPeriodConfigurations;
    public DbSet<ManagementReviewPolicy> ManagementReviewPolicies => db.ManagementReviewPolicies;
    public DbSet<InternalAuditCycle> InternalAuditCycles => db.InternalAuditCycles;
    public DbSet<InternalAuditAttestation> InternalAuditAttestations => db.InternalAuditAttestations;
    public DbSet<ComplianceReviewChecklistItem> ComplianceReviewChecklistItems => db.ComplianceReviewChecklistItems;
    public DbSet<ComplianceException> ComplianceExceptions => db.ComplianceExceptions;
    public DbSet<AppUser> Users => db.Users;
    public DbSet<EnrollmentRequest> EnrollmentRequests => db.EnrollmentRequests;
    public DbSet<PersonnelProfile> PersonnelProfiles => db.PersonnelProfiles;
    public DbSet<Contract> Contracts => db.Contracts;
    public DbSet<ContractOptionYear> ContractOptionYears => db.ContractOptionYears;
    public DbSet<ContractPricing> ContractPricings => db.ContractPricings;
    public DbSet<TaskOrder> TaskOrders => db.TaskOrders;
    public DbSet<Clin> Clins => db.Clins;
    public DbSet<WbsNode> WbsNodes => db.WbsNodes;
    public DbSet<ChargeCode> ChargeCodes => db.ChargeCodes;
    public DbSet<AllowabilityRule> AllowabilityRules => db.AllowabilityRules;
    public DbSet<Assignment> Assignments => db.Assignments;
    public DbSet<TimeChargeOverrideApproval> TimeChargeOverrideApprovals => db.TimeChargeOverrideApprovals;
    public DbSet<OvertimeAllowanceApproval> OvertimeAllowanceApprovals => db.OvertimeAllowanceApprovals;
    public DbSet<FuturePtoApproval> FuturePtoApprovals => db.FuturePtoApprovals;
    public DbSet<FuturePtoApprovalRequest> FuturePtoApprovalRequests => db.FuturePtoApprovalRequests;
    public DbSet<AccountingPeriod> AccountingPeriods => db.AccountingPeriods;
    public DbSet<Timesheet> Timesheets => db.Timesheets;
    public DbSet<TimesheetDay> TimesheetDays => db.TimesheetDays;
    public DbSet<TimesheetLine> TimesheetLines => db.TimesheetLines;
    public DbSet<TimesheetExpense> TimesheetExpenses => db.TimesheetExpenses;
    public DbSet<TimesheetWorkNote> TimesheetWorkNotes => db.TimesheetWorkNotes;
    public DbSet<WeeklyStatusReport> WeeklyStatusReports => db.WeeklyStatusReports;
    public DbSet<CloseChecklist> CloseChecklists => db.CloseChecklists;
    public DbSet<TimesheetApproval> TimesheetApprovals => db.TimesheetApprovals;
    public DbSet<TimesheetVersion> TimesheetVersions => db.TimesheetVersions;
    public DbSet<CorrectionRequest> CorrectionRequests => db.CorrectionRequests;
    public DbSet<CorrectionApproval> CorrectionApprovals => db.CorrectionApprovals;
    public DbSet<AuditEvent> AuditEvents => db.AuditEvents;
    public DbSet<ChartOfAccount> ChartOfAccounts => db.ChartOfAccounts;
    public DbSet<JournalEntry> JournalEntries => db.JournalEntries;
    public DbSet<JournalEntryApproval> JournalEntryApprovals => db.JournalEntryApprovals;
    public DbSet<JournalLine> JournalLines => db.JournalLines;
    public DbSet<IndirectPool> IndirectPools => db.IndirectPools;
    public DbSet<AllocationBase> AllocationBases => db.AllocationBases;
    public DbSet<RateCalculation> RateCalculations => db.RateCalculations;
    public DbSet<AppliedBurdenEntry> AppliedBurdenEntries => db.AppliedBurdenEntries;
    public DbSet<AiPrompt> AiPrompts => db.AiPrompts;
    public DbSet<ExternalServiceConfig> ExternalServiceConfigs => db.ExternalServiceConfigs;
    public DbSet<PasskeyCredential> PasskeyCredentials => db.PasskeyCredentials;
    public DbSet<PayrollBatch> PayrollBatches => db.PayrollBatches;
    public DbSet<PayrollLine> PayrollLines => db.PayrollLines;
    public DbSet<PayrollImportProfile> PayrollImportProfiles => db.PayrollImportProfiles;
    public DbSet<BillingRun> BillingRuns => db.BillingRuns;
    public DbSet<Invoice> Invoices => db.Invoices;
    public DbSet<InvoiceLine> InvoiceLines => db.InvoiceLines;
    public DbSet<BillingCeiling> BillingCeilings => db.BillingCeilings;
    public DbSet<BilledCostLink> BilledCostLinks => db.BilledCostLinks;

    public int SaveChanges() => db.SaveChanges();
}
