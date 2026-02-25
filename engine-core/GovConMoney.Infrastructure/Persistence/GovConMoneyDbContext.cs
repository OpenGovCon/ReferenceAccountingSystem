using GovConMoney.Domain.Entities;
using GovConMoney.Application.Abstractions;
using GovConMoney.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace GovConMoney.Infrastructure.Persistence;

public sealed class GovConMoneyDbContext(
    DbContextOptions<GovConMoneyDbContext> options,
    ITenantContext? tenantContext = null) : DbContext(options)
{
    private readonly ITenantContext? _tenantContext = tenantContext;
    private Guid CurrentTenantId => _tenantContext?.TenantId ?? Guid.Empty;

    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<UserNotification> UserNotifications => Set<UserNotification>();
    public DbSet<UserNotificationState> UserNotificationStates => Set<UserNotificationState>();
    public DbSet<WorkPeriodConfiguration> WorkPeriodConfigurations => Set<WorkPeriodConfiguration>();
    public DbSet<ManagementReviewPolicy> ManagementReviewPolicies => Set<ManagementReviewPolicy>();
    public DbSet<InternalAuditCycle> InternalAuditCycles => Set<InternalAuditCycle>();
    public DbSet<InternalAuditAttestation> InternalAuditAttestations => Set<InternalAuditAttestation>();
    public DbSet<ComplianceReviewChecklistItem> ComplianceReviewChecklistItems => Set<ComplianceReviewChecklistItem>();
    public DbSet<ComplianceException> ComplianceExceptions => Set<ComplianceException>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<EnrollmentRequest> EnrollmentRequests => Set<EnrollmentRequest>();
    public DbSet<PersonnelProfile> PersonnelProfiles => Set<PersonnelProfile>();
    public DbSet<Contract> Contracts => Set<Contract>();
    public DbSet<ContractOptionYear> ContractOptionYears => Set<ContractOptionYear>();
    public DbSet<ContractPricing> ContractPricings => Set<ContractPricing>();
    public DbSet<TaskOrder> TaskOrders => Set<TaskOrder>();
    public DbSet<Clin> Clins => Set<Clin>();
    public DbSet<WbsNode> WbsNodes => Set<WbsNode>();
    public DbSet<ChargeCode> ChargeCodes => Set<ChargeCode>();
    public DbSet<AllowabilityRule> AllowabilityRules => Set<AllowabilityRule>();
    public DbSet<Assignment> Assignments => Set<Assignment>();
    public DbSet<TimeChargeOverrideApproval> TimeChargeOverrideApprovals => Set<TimeChargeOverrideApproval>();
    public DbSet<OvertimeAllowanceApproval> OvertimeAllowanceApprovals => Set<OvertimeAllowanceApproval>();
    public DbSet<FuturePtoApproval> FuturePtoApprovals => Set<FuturePtoApproval>();
    public DbSet<FuturePtoApprovalRequest> FuturePtoApprovalRequests => Set<FuturePtoApprovalRequest>();
    public DbSet<AccountingPeriod> AccountingPeriods => Set<AccountingPeriod>();
    public DbSet<Timesheet> Timesheets => Set<Timesheet>();
    public DbSet<TimesheetDay> TimesheetDays => Set<TimesheetDay>();
    public DbSet<TimesheetLine> TimesheetLines => Set<TimesheetLine>();
    public DbSet<TimesheetExpense> TimesheetExpenses => Set<TimesheetExpense>();
    public DbSet<TimesheetWorkNote> TimesheetWorkNotes => Set<TimesheetWorkNote>();
    public DbSet<WeeklyStatusReport> WeeklyStatusReports => Set<WeeklyStatusReport>();
    public DbSet<CloseChecklist> CloseChecklists => Set<CloseChecklist>();
    public DbSet<TimesheetApproval> TimesheetApprovals => Set<TimesheetApproval>();
    public DbSet<TimesheetVersion> TimesheetVersions => Set<TimesheetVersion>();
    public DbSet<CorrectionRequest> CorrectionRequests => Set<CorrectionRequest>();
    public DbSet<CorrectionApproval> CorrectionApprovals => Set<CorrectionApproval>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<ChartOfAccount> ChartOfAccounts => Set<ChartOfAccount>();
    public DbSet<JournalEntry> JournalEntries => Set<JournalEntry>();
    public DbSet<JournalEntryApproval> JournalEntryApprovals => Set<JournalEntryApproval>();
    public DbSet<JournalLine> JournalLines => Set<JournalLine>();
    public DbSet<IndirectPool> IndirectPools => Set<IndirectPool>();
    public DbSet<AllocationBase> AllocationBases => Set<AllocationBase>();
    public DbSet<RateCalculation> RateCalculations => Set<RateCalculation>();
    public DbSet<AppliedBurdenEntry> AppliedBurdenEntries => Set<AppliedBurdenEntry>();
    public DbSet<AiPrompt> AiPrompts => Set<AiPrompt>();
    public DbSet<ExternalServiceConfig> ExternalServiceConfigs => Set<ExternalServiceConfig>();
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
    public DbSet<PayrollBatch> PayrollBatches => Set<PayrollBatch>();
    public DbSet<PayrollLine> PayrollLines => Set<PayrollLine>();
    public DbSet<PayrollImportProfile> PayrollImportProfiles => Set<PayrollImportProfile>();
    public DbSet<BillingRun> BillingRuns => Set<BillingRun>();
    public DbSet<Invoice> Invoices => Set<Invoice>();
    public DbSet<InvoiceLine> InvoiceLines => Set<InvoiceLine>();
    public DbSet<BillingCeiling> BillingCeilings => Set<BillingCeiling>();
    public DbSet<BilledCostLink> BilledCostLinks => Set<BilledCostLink>();

    public override int SaveChanges()
    {
        EnforceAppendOnlyAndLedgerImmutability();
        return base.SaveChanges();
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        EnforceAppendOnlyAndLedgerImmutability();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        EnforceAppendOnlyAndLedgerImmutability();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        EnforceAppendOnlyAndLedgerImmutability();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            var clrType = entityType.ClrType;
            if (!typeof(ITenantScoped).IsAssignableFrom(clrType))
            {
                continue;
            }

            modelBuilder.Entity(clrType).HasIndex(nameof(ITenantScoped.TenantId));
            modelBuilder.Entity(clrType).HasQueryFilter(BuildCombinedFilter(clrType));
        }

        modelBuilder.Entity<Timesheet>()
            .HasIndex(x => new { x.TenantId, x.UserId, x.PeriodStart, x.PeriodEnd });

        modelBuilder.Entity<ManagementReviewPolicy>()
            .HasIndex(x => x.TenantId)
            .IsUnique();

        modelBuilder.Entity<InternalAuditCycle>()
            .HasIndex(x => new { x.TenantId, x.AccountingPeriodId })
            .IsUnique();

        modelBuilder.Entity<InternalAuditCycle>()
            .HasIndex(x => new { x.TenantId, x.PeriodStart, x.PeriodEnd, x.Status });

        modelBuilder.Entity<InternalAuditAttestation>()
            .HasIndex(x => new { x.TenantId, x.InternalAuditCycleId, x.AttestationType, x.AttestedByUserId });

        modelBuilder.Entity<ComplianceReviewChecklistItem>()
            .HasIndex(x => new { x.TenantId, x.InternalAuditCycleId, x.ClauseRef });

        modelBuilder.Entity<ComplianceException>()
            .HasIndex(x => new { x.TenantId, x.InternalAuditCycleId, x.Status, x.Category });

        modelBuilder.Entity<AuditEvent>()
            .HasIndex(x => new { x.TenantId, x.OccurredAtUtc });

        modelBuilder.Entity<AppUser>()
            .HasIndex(x => new { x.TenantId, x.EmployeeExternalId });

        modelBuilder.Entity<PayrollBatch>()
            .HasIndex(x => new { x.TenantId, x.ExternalBatchId });

        modelBuilder.Entity<PayrollLine>()
            .HasIndex(x => new { x.TenantId, x.PayrollBatchId, x.EmployeeExternalId });

        modelBuilder.Entity<PayrollImportProfile>()
            .HasIndex(x => new { x.TenantId, x.Name });

        modelBuilder.Entity<RateCalculation>()
            .HasIndex(x => new { x.TenantId, x.IndirectPoolId, x.PeriodStart, x.PeriodEnd, x.Version });

        modelBuilder.Entity<AppliedBurdenEntry>()
            .HasIndex(x => new { x.TenantId, x.IndirectPoolId, x.PeriodStart, x.PeriodEnd });

        modelBuilder.Entity<BillingRun>()
            .HasIndex(x => new { x.TenantId, x.PeriodStart, x.PeriodEnd, x.Status });

        modelBuilder.Entity<Invoice>()
            .HasIndex(x => new { x.TenantId, x.ContractId, x.PeriodStart, x.PeriodEnd, x.Status });

        modelBuilder.Entity<InvoiceLine>()
            .HasIndex(x => new { x.TenantId, x.ContractId, x.ChargeCodeId, x.CostType });

        modelBuilder.Entity<BillingCeiling>()
            .HasIndex(x => new { x.TenantId, x.ContractId, x.IsActive });

        modelBuilder.Entity<FuturePtoApproval>()
            .HasIndex(x => new { x.TenantId, x.UserId, x.WorkDate });

        modelBuilder.Entity<FuturePtoApprovalRequest>()
            .HasIndex(x => new { x.TenantId, x.UserId, x.WorkDate })
            .IsUnique();
    }

    private LambdaExpression BuildCombinedFilter(Type entityType)
    {
        var parameter = Expression.Parameter(entityType, "e");

        var tenantProperty = Expression.Property(parameter, nameof(ITenantScoped.TenantId));
        var tenantValue = Expression.Property(Expression.Constant(this), nameof(CurrentTenantId));
        var emptyTenant = Expression.Equal(tenantValue, Expression.Constant(Guid.Empty));
        var tenantMatch = Expression.Equal(tenantProperty, tenantValue);
        Expression body = Expression.OrElse(emptyTenant, tenantMatch);

        if (!typeof(ISoftDeletable).IsAssignableFrom(entityType))
        {
            return Expression.Lambda(body, parameter);
        }

        var isDeletedProperty = Expression.Property(parameter, nameof(ISoftDeletable.IsDeleted));
        var notDeleted = Expression.Equal(isDeletedProperty, Expression.Constant(false));
        body = Expression.AndAlso(body, notDeleted);
        return Expression.Lambda(body, parameter);
    }

    private void EnforceAppendOnlyAndLedgerImmutability()
    {
        foreach (var entry in ChangeTracker.Entries())
        {
            if (entry.Entity is AuditEvent)
            {
                if (entry.State is EntityState.Modified or EntityState.Deleted)
                {
                    throw new InvalidOperationException("AuditEvent is append-only and cannot be modified or deleted.");
                }

                continue;
            }

            if (entry.Entity is JournalLine)
            {
                if (entry.State is EntityState.Modified or EntityState.Deleted)
                {
                    throw new InvalidOperationException("JournalLine is immutable and cannot be modified or deleted.");
                }

                continue;
            }

            if (entry.Entity is not JournalEntry journalEntry)
            {
                if (entry.Entity is InternalAuditCycle reviewCycle && entry.State == EntityState.Modified)
                {
                    var originalReviewStatus = (InternalAuditCycleStatus)entry.OriginalValues[nameof(InternalAuditCycle.Status)]!;
                    var currentStatus = reviewCycle.Status;
                    if (originalReviewStatus == InternalAuditCycleStatus.Closed)
                    {
                        if (currentStatus != InternalAuditCycleStatus.Closed)
                        {
                            throw new InvalidOperationException("Closed InternalAuditCycle is immutable and cannot transition to another status.");
                        }
                    }
                    else if (originalReviewStatus == InternalAuditCycleStatus.Approved)
                    {
                        if (currentStatus != InternalAuditCycleStatus.Approved && currentStatus != InternalAuditCycleStatus.Closed)
                        {
                            throw new InvalidOperationException("Approved InternalAuditCycle can only remain approved or transition to closed.");
                        }
                    }
                }

                continue;
            }

            if (entry.State == EntityState.Deleted)
            {
                throw new InvalidOperationException("JournalEntry is immutable and cannot be deleted.");
            }

            if (entry.State != EntityState.Modified)
            {
                continue;
            }

            var originalStatus = (JournalEntryStatus)entry.OriginalValues[nameof(JournalEntry.Status)]!;
            if (originalStatus == JournalEntryStatus.Posted)
            {
                var currentStatus = journalEntry.Status;
                if (currentStatus == JournalEntryStatus.Reversed)
                {
                    continue;
                }

                throw new InvalidOperationException("Posted JournalEntry is immutable and cannot be modified.");
            }

            if (originalStatus == JournalEntryStatus.Reversed)
            {
                throw new InvalidOperationException("Reversed JournalEntry is immutable and cannot be modified.");
            }
        }
    }
}
