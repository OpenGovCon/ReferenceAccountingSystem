using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GovConMoney.Web.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchemaWeb : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AccountingPeriods",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    StartDate = table.Column<DateOnly>(type: "date", nullable: false),
                    EndDate = table.Column<DateOnly>(type: "date", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountingPeriods", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AiPrompts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Function = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Prompt = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AiPrompts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AllocationBases",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IndirectPoolId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    BaseCostType = table.Column<int>(type: "int", nullable: false),
                    BaseMethod = table.Column<int>(type: "int", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AllocationBases", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AllowabilityRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CostType = table.Column<int>(type: "int", nullable: false),
                    RuleName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RuleDescription = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RequiresComment = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AllowabilityRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AppliedBurdenEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetLineId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IndirectPoolId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RateCalculationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PeriodStart = table.Column<DateOnly>(type: "date", nullable: false),
                    PeriodEnd = table.Column<DateOnly>(type: "date", nullable: false),
                    ContractId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TaskOrderId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClinId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WbsNodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ChargeCodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    BaseAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    BurdenAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    IsAdjustment = table.Column<bool>(type: "bit", nullable: false),
                    AppliedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    PostedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PostedJournalEntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppliedBurdenEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Assignments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ChargeCodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EffectiveStartDate = table.Column<DateOnly>(type: "date", nullable: false),
                    EffectiveEndDate = table.Column<DateOnly>(type: "date", nullable: false),
                    SupervisorOverrideAllowed = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Assignments", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EntityType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EntityId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EventType = table.Column<int>(type: "int", nullable: false),
                    ActorUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ActorRoles = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ReasonForChange = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    BeforeJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AfterJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CorrelationId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IpAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    UserAgent = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BilledCostLinks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InvoiceLineId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SourceEntityType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SourceEntityId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Amount = table.Column<decimal>(type: "decimal(18,2)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BilledCostLinks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BillingCeilings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ContractId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FundedAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    CeilingAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    EffectiveStartDate = table.Column<DateOnly>(type: "date", nullable: false),
                    EffectiveEndDate = table.Column<DateOnly>(type: "date", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BillingCeilings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BillingRuns",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PeriodStart = table.Column<DateOnly>(type: "date", nullable: false),
                    PeriodEnd = table.Column<DateOnly>(type: "date", nullable: false),
                    RunDateUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PostedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    PostedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BillingRuns", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ChargeCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WbsNodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Code = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CostType = table.Column<int>(type: "int", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ChargeCodes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ChartOfAccounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountNumber = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CostType = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ChartOfAccounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Clins",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TaskOrderId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Number = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Clins", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CloseChecklists",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountingPeriodId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CompletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    StepsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CloseChecklists", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ComplianceExceptions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InternalAuditCycleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ChecklistItemId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Severity = table.Column<int>(type: "int", nullable: false),
                    Category = table.Column<int>(type: "int", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RootCause = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RemediationPlan = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    OwnerUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    DueDate = table.Column<DateOnly>(type: "date", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: false),
                    ResolvedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ResolvedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ResolutionNotes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ComplianceExceptions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ComplianceReviewChecklistItems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InternalAuditCycleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClauseRef = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ControlName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Result = table.Column<int>(type: "int", nullable: true),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ComplianceReviewChecklistItems", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ContractOptionYears",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ContractId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OptionYearNumber = table.Column<int>(type: "int", nullable: false),
                    StartDate = table.Column<DateOnly>(type: "date", nullable: false),
                    EndDate = table.Column<DateOnly>(type: "date", nullable: false),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ContractOptionYears", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ContractPricings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ContractId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    LaborCategory = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Site = table.Column<int>(type: "int", nullable: false),
                    BaseHourlyRate = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    EscalationPercent = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    FeePercent = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    EffectiveStartDate = table.Column<DateOnly>(type: "date", nullable: false),
                    EffectiveEndDate = table.Column<DateOnly>(type: "date", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ContractPricings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Contracts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ContractNumber = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    BudgetAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    ContractType = table.Column<int>(type: "int", nullable: false),
                    RequiresClinTracking = table.Column<bool>(type: "bit", nullable: false),
                    BaseYearStartDate = table.Column<DateOnly>(type: "date", nullable: false),
                    BaseYearEndDate = table.Column<DateOnly>(type: "date", nullable: false),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Contracts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CorrectionApprovals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CorrectionRequestId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ApproverUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CorrectionApprovals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CorrectionRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ReasonForChange = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Approved = table.Column<bool>(type: "bit", nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CorrectionRequests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EnrollmentRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Email = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RequestedRole = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    SubmittedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ReviewedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ReviewedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ReviewNote = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EnrollmentRequests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ExternalServiceConfigs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ServiceName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ApiKeyMasked = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Endpoint = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalServiceConfigs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "IndirectPools",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EffectiveStartDate = table.Column<DateOnly>(type: "date", nullable: false),
                    EffectiveEndDate = table.Column<DateOnly>(type: "date", nullable: false),
                    PoolCostType = table.Column<int>(type: "int", nullable: false),
                    BaseCostType = table.Column<int>(type: "int", nullable: false),
                    ExcludeUnallowable = table.Column<bool>(type: "bit", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IndirectPools", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "InternalAuditAttestations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InternalAuditCycleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AttestationType = table.Column<int>(type: "int", nullable: false),
                    AttestedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AttestedByRoles = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AttestedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Statement = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InternalAuditAttestations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "InternalAuditCycles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountingPeriodId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ReviewType = table.Column<int>(type: "int", nullable: false),
                    PeriodStart = table.Column<DateOnly>(type: "date", nullable: false),
                    PeriodEnd = table.Column<DateOnly>(type: "date", nullable: false),
                    DueDate = table.Column<DateOnly>(type: "date", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    TieOutReviewCompleted = table.Column<bool>(type: "bit", nullable: false),
                    UnallowableReviewCompleted = table.Column<bool>(type: "bit", nullable: false),
                    BillingReviewCompleted = table.Column<bool>(type: "bit", nullable: false),
                    MonthlyCloseReviewCompleted = table.Column<bool>(type: "bit", nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    SubmittedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    SubmittedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CompletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ClosedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ClosedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Summary = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InternalAuditCycles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "InvoiceLines",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InvoiceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ContractId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TaskOrderId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClinId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WbsNodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ChargeCodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CostType = table.Column<int>(type: "int", nullable: false),
                    CostElement = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Quantity = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Rate = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Amount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    IsAllowable = table.Column<bool>(type: "bit", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InvoiceLines", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Invoices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    BillingRunId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ContractId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InvoiceNumber = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PeriodStart = table.Column<DateOnly>(type: "date", nullable: false),
                    PeriodEnd = table.Column<DateOnly>(type: "date", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    TotalAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    PostedJournalEntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Invoices", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "JournalEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EntryDate = table.Column<DateOnly>(type: "date", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EntryType = table.Column<int>(type: "int", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    IsReversal = table.Column<bool>(type: "bit", nullable: false),
                    ReversalOfJournalEntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    RequestedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    SubmittedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PostedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DraftLinesJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AttachmentRefs = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JournalEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "JournalEntryApprovals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    JournalEntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AttachmentRefs = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JournalEntryApprovals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "JournalLines",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    JournalEntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Debit = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Credit = table.Column<decimal>(type: "decimal(18,2)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JournalLines", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ManagementReviewPolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequireManagerApprovalForBillingAboveThreshold = table.Column<bool>(type: "bit", nullable: false),
                    BillingManagerApprovalThreshold = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    RequireManagerCoSignForAdjustingAboveThreshold = table.Column<bool>(type: "bit", nullable: false),
                    AdjustingManagerCoSignThreshold = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    EnablePeriodicInternalAuditAttestation = table.Column<bool>(type: "bit", nullable: false),
                    InternalAuditCadenceDays = table.Column<int>(type: "int", nullable: false),
                    InternalAuditDueDaysAfterPeriodEnd = table.Column<int>(type: "int", nullable: false),
                    RequireManagerInternalAuditAttestation = table.Column<bool>(type: "bit", nullable: false),
                    RequireComplianceInternalAuditAttestation = table.Column<bool>(type: "bit", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ManagementReviewPolicies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OvertimeAllowanceApprovals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkDate = table.Column<DateOnly>(type: "date", nullable: false),
                    ApprovedOvertimeMinutes = table.Column<int>(type: "int", nullable: false),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OvertimeAllowanceApprovals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PasskeyCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PublicKey = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    UserHandle = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Transports = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Aaguid = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasskeyCredentials", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PayrollBatches",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ExternalBatchId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    SourceSystem = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PeriodStart = table.Column<DateOnly>(type: "date", nullable: false),
                    PeriodEnd = table.Column<DateOnly>(type: "date", nullable: false),
                    ImportedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ImportedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SourceChecksum = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PayrollBatches", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PayrollImportProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    SourceSystem = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Delimiter = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    HasHeaderRow = table.Column<bool>(type: "bit", nullable: false),
                    EmployeeExternalIdColumn = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    LaborAmountColumn = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    FringeAmountColumn = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TaxAmountColumn = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    OtherAmountColumn = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    NotesColumn = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RequiredHeadersCsv = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RequireKnownEmployeeExternalId = table.Column<bool>(type: "bit", nullable: false),
                    DisallowDuplicateEmployeeExternalIds = table.Column<bool>(type: "bit", nullable: false),
                    RequirePositiveLaborAmount = table.Column<bool>(type: "bit", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PayrollImportProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PayrollLines",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PayrollBatchId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EmployeeExternalId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    LaborAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    FringeAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    TaxAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    OtherAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PayrollLines", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PersonnelProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SupervisorUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    HourlyRate = table.Column<decimal>(type: "decimal(18,2)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PersonnelProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RateCalculations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IndirectPoolId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PeriodStart = table.Column<DateOnly>(type: "date", nullable: false),
                    PeriodEnd = table.Column<DateOnly>(type: "date", nullable: false),
                    PoolCost = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    AllocationBaseTotal = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Rate = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Version = table.Column<int>(type: "int", nullable: false),
                    IsFinal = table.Column<bool>(type: "bit", nullable: false),
                    CalculatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CalculatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ReviewStatus = table.Column<int>(type: "int", nullable: false),
                    SubmittedForReviewByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    SubmittedForReviewAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ReviewedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ReviewedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ReviewNote = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RateCalculations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TaskOrders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ContractId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Number = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    BudgetAmount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    RequiresClinTracking = table.Column<bool>(type: "bit", nullable: false),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TaskOrders", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TimeChargeOverrideApprovals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ChargeCodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkDate = table.Column<DateOnly>(type: "date", nullable: false),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimeChargeOverrideApprovals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TimesheetApprovals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ApproverUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimesheetApprovals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TimesheetDays",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkDate = table.Column<DateOnly>(type: "date", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimesheetDays", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TimesheetExpenses",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ExpenseDate = table.Column<DateOnly>(type: "date", nullable: false),
                    ChargeCodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CostType = table.Column<int>(type: "int", nullable: false),
                    Amount = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
                    Category = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AccountingCategory = table.Column<int>(type: "int", nullable: false),
                    AccountingCategoryAssignedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    AccountingCategoryAssignedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: false),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RejectionReason = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    VoidedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    VoidedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    VoidReason = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimesheetExpenses", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TimesheetLines",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkDate = table.Column<DateOnly>(type: "date", nullable: false),
                    ChargeCodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Minutes = table.Column<int>(type: "int", nullable: false),
                    CostType = table.Column<int>(type: "int", nullable: false),
                    Comment = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimesheetLines", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Timesheets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PeriodStart = table.Column<DateOnly>(type: "date", nullable: false),
                    PeriodEnd = table.Column<DateOnly>(type: "date", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    Attestation = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    SubmittedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    VersionNumber = table.Column<int>(type: "int", nullable: false),
                    IsComplianceFlagged = table.Column<bool>(type: "bit", nullable: false),
                    ComplianceIssuesJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LastComplianceCheckedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PostedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PostedJournalEntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Timesheets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TimesheetVersions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VersionNumber = table.Column<int>(type: "int", nullable: false),
                    SnapshotJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimesheetVersions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TimesheetWorkNotes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Note = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimesheetWorkNotes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserNotifications",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Title = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Message = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Category = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TargetUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    TargetRole = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserNotifications", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserNotificationStates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    NotificationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IsRead = table.Column<bool>(type: "bit", nullable: false),
                    ReadAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserNotificationStates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Email = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EmployeeExternalId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    IsDisabled = table.Column<bool>(type: "bit", nullable: false),
                    MfaEnabled = table.Column<bool>(type: "bit", nullable: false),
                    PasskeyRequired = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WbsNodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClinId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ParentWbsNodeId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Code = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WbsNodes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WeeklyStatusReports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TimesheetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Narrative = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WeeklyStatusReports", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WorkPeriodConfigurations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WeekStartDay = table.Column<int>(type: "int", nullable: false),
                    PeriodLengthDays = table.Column<int>(type: "int", nullable: false),
                    DailyEntryRequired = table.Column<bool>(type: "bit", nullable: false),
                    DailyEntryGraceDays = table.Column<int>(type: "int", nullable: false),
                    DailyEntryHardFail = table.Column<bool>(type: "bit", nullable: false),
                    DailyEntryIncludeWeekends = table.Column<bool>(type: "bit", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkPeriodConfigurations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccountingPeriods_TenantId",
                table: "AccountingPeriods",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AiPrompts_TenantId",
                table: "AiPrompts",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AllocationBases_TenantId",
                table: "AllocationBases",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AllowabilityRules_TenantId",
                table: "AllowabilityRules",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AppliedBurdenEntries_TenantId",
                table: "AppliedBurdenEntries",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AppliedBurdenEntries_TenantId_IndirectPoolId_PeriodStart_PeriodEnd",
                table: "AppliedBurdenEntries",
                columns: new[] { "TenantId", "IndirectPoolId", "PeriodStart", "PeriodEnd" });

            migrationBuilder.CreateIndex(
                name: "IX_Assignments_TenantId",
                table: "Assignments",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_TenantId",
                table: "AuditEvents",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_TenantId_OccurredAtUtc",
                table: "AuditEvents",
                columns: new[] { "TenantId", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_BilledCostLinks_TenantId",
                table: "BilledCostLinks",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_BillingCeilings_TenantId",
                table: "BillingCeilings",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_BillingCeilings_TenantId_ContractId_IsActive",
                table: "BillingCeilings",
                columns: new[] { "TenantId", "ContractId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_BillingRuns_TenantId",
                table: "BillingRuns",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_BillingRuns_TenantId_PeriodStart_PeriodEnd_Status",
                table: "BillingRuns",
                columns: new[] { "TenantId", "PeriodStart", "PeriodEnd", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_ChargeCodes_TenantId",
                table: "ChargeCodes",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ChartOfAccounts_TenantId",
                table: "ChartOfAccounts",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Clins_TenantId",
                table: "Clins",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_CloseChecklists_TenantId",
                table: "CloseChecklists",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ComplianceExceptions_TenantId",
                table: "ComplianceExceptions",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ComplianceExceptions_TenantId_InternalAuditCycleId_Status_Category",
                table: "ComplianceExceptions",
                columns: new[] { "TenantId", "InternalAuditCycleId", "Status", "Category" });

            migrationBuilder.CreateIndex(
                name: "IX_ComplianceReviewChecklistItems_TenantId",
                table: "ComplianceReviewChecklistItems",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ComplianceReviewChecklistItems_TenantId_InternalAuditCycleId_ClauseRef",
                table: "ComplianceReviewChecklistItems",
                columns: new[] { "TenantId", "InternalAuditCycleId", "ClauseRef" });

            migrationBuilder.CreateIndex(
                name: "IX_ContractOptionYears_TenantId",
                table: "ContractOptionYears",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ContractPricings_TenantId",
                table: "ContractPricings",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Contracts_TenantId",
                table: "Contracts",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_CorrectionApprovals_TenantId",
                table: "CorrectionApprovals",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_CorrectionRequests_TenantId",
                table: "CorrectionRequests",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentRequests_TenantId",
                table: "EnrollmentRequests",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ExternalServiceConfigs_TenantId",
                table: "ExternalServiceConfigs",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_IndirectPools_TenantId",
                table: "IndirectPools",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_InternalAuditAttestations_TenantId",
                table: "InternalAuditAttestations",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_InternalAuditAttestations_TenantId_InternalAuditCycleId_AttestationType_AttestedByUserId",
                table: "InternalAuditAttestations",
                columns: new[] { "TenantId", "InternalAuditCycleId", "AttestationType", "AttestedByUserId" });

            migrationBuilder.CreateIndex(
                name: "IX_InternalAuditCycles_TenantId",
                table: "InternalAuditCycles",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_InternalAuditCycles_TenantId_AccountingPeriodId",
                table: "InternalAuditCycles",
                columns: new[] { "TenantId", "AccountingPeriodId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_InternalAuditCycles_TenantId_PeriodStart_PeriodEnd_Status",
                table: "InternalAuditCycles",
                columns: new[] { "TenantId", "PeriodStart", "PeriodEnd", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_InvoiceLines_TenantId",
                table: "InvoiceLines",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_InvoiceLines_TenantId_ContractId_ChargeCodeId_CostType",
                table: "InvoiceLines",
                columns: new[] { "TenantId", "ContractId", "ChargeCodeId", "CostType" });

            migrationBuilder.CreateIndex(
                name: "IX_Invoices_TenantId",
                table: "Invoices",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Invoices_TenantId_ContractId_PeriodStart_PeriodEnd_Status",
                table: "Invoices",
                columns: new[] { "TenantId", "ContractId", "PeriodStart", "PeriodEnd", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_JournalEntries_TenantId",
                table: "JournalEntries",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_JournalEntryApprovals_TenantId",
                table: "JournalEntryApprovals",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_JournalLines_TenantId",
                table: "JournalLines",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ManagementReviewPolicies_TenantId",
                table: "ManagementReviewPolicies",
                column: "TenantId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OvertimeAllowanceApprovals_TenantId",
                table: "OvertimeAllowanceApprovals",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_PasskeyCredentials_TenantId",
                table: "PasskeyCredentials",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_PayrollBatches_TenantId",
                table: "PayrollBatches",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_PayrollBatches_TenantId_ExternalBatchId",
                table: "PayrollBatches",
                columns: new[] { "TenantId", "ExternalBatchId" });

            migrationBuilder.CreateIndex(
                name: "IX_PayrollImportProfiles_TenantId",
                table: "PayrollImportProfiles",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_PayrollImportProfiles_TenantId_Name",
                table: "PayrollImportProfiles",
                columns: new[] { "TenantId", "Name" });

            migrationBuilder.CreateIndex(
                name: "IX_PayrollLines_TenantId",
                table: "PayrollLines",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_PayrollLines_TenantId_PayrollBatchId_EmployeeExternalId",
                table: "PayrollLines",
                columns: new[] { "TenantId", "PayrollBatchId", "EmployeeExternalId" });

            migrationBuilder.CreateIndex(
                name: "IX_PersonnelProfiles_TenantId",
                table: "PersonnelProfiles",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_RateCalculations_TenantId",
                table: "RateCalculations",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_RateCalculations_TenantId_IndirectPoolId_PeriodStart_PeriodEnd_Version",
                table: "RateCalculations",
                columns: new[] { "TenantId", "IndirectPoolId", "PeriodStart", "PeriodEnd", "Version" });

            migrationBuilder.CreateIndex(
                name: "IX_TaskOrders_TenantId",
                table: "TaskOrders",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TimeChargeOverrideApprovals_TenantId",
                table: "TimeChargeOverrideApprovals",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TimesheetApprovals_TenantId",
                table: "TimesheetApprovals",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TimesheetDays_TenantId",
                table: "TimesheetDays",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TimesheetExpenses_TenantId",
                table: "TimesheetExpenses",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TimesheetLines_TenantId",
                table: "TimesheetLines",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Timesheets_TenantId",
                table: "Timesheets",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Timesheets_TenantId_UserId_PeriodStart_PeriodEnd",
                table: "Timesheets",
                columns: new[] { "TenantId", "UserId", "PeriodStart", "PeriodEnd" });

            migrationBuilder.CreateIndex(
                name: "IX_TimesheetVersions_TenantId",
                table: "TimesheetVersions",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TimesheetWorkNotes_TenantId",
                table: "TimesheetWorkNotes",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_UserNotifications_TenantId",
                table: "UserNotifications",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_UserNotificationStates_TenantId",
                table: "UserNotificationStates",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_TenantId",
                table: "Users",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_TenantId_EmployeeExternalId",
                table: "Users",
                columns: new[] { "TenantId", "EmployeeExternalId" });

            migrationBuilder.CreateIndex(
                name: "IX_WbsNodes_TenantId",
                table: "WbsNodes",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_WeeklyStatusReports_TenantId",
                table: "WeeklyStatusReports",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkPeriodConfigurations_TenantId",
                table: "WorkPeriodConfigurations",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AccountingPeriods");

            migrationBuilder.DropTable(
                name: "AiPrompts");

            migrationBuilder.DropTable(
                name: "AllocationBases");

            migrationBuilder.DropTable(
                name: "AllowabilityRules");

            migrationBuilder.DropTable(
                name: "AppliedBurdenEntries");

            migrationBuilder.DropTable(
                name: "Assignments");

            migrationBuilder.DropTable(
                name: "AuditEvents");

            migrationBuilder.DropTable(
                name: "BilledCostLinks");

            migrationBuilder.DropTable(
                name: "BillingCeilings");

            migrationBuilder.DropTable(
                name: "BillingRuns");

            migrationBuilder.DropTable(
                name: "ChargeCodes");

            migrationBuilder.DropTable(
                name: "ChartOfAccounts");

            migrationBuilder.DropTable(
                name: "Clins");

            migrationBuilder.DropTable(
                name: "CloseChecklists");

            migrationBuilder.DropTable(
                name: "ComplianceExceptions");

            migrationBuilder.DropTable(
                name: "ComplianceReviewChecklistItems");

            migrationBuilder.DropTable(
                name: "ContractOptionYears");

            migrationBuilder.DropTable(
                name: "ContractPricings");

            migrationBuilder.DropTable(
                name: "Contracts");

            migrationBuilder.DropTable(
                name: "CorrectionApprovals");

            migrationBuilder.DropTable(
                name: "CorrectionRequests");

            migrationBuilder.DropTable(
                name: "EnrollmentRequests");

            migrationBuilder.DropTable(
                name: "ExternalServiceConfigs");

            migrationBuilder.DropTable(
                name: "IndirectPools");

            migrationBuilder.DropTable(
                name: "InternalAuditAttestations");

            migrationBuilder.DropTable(
                name: "InternalAuditCycles");

            migrationBuilder.DropTable(
                name: "InvoiceLines");

            migrationBuilder.DropTable(
                name: "Invoices");

            migrationBuilder.DropTable(
                name: "JournalEntries");

            migrationBuilder.DropTable(
                name: "JournalEntryApprovals");

            migrationBuilder.DropTable(
                name: "JournalLines");

            migrationBuilder.DropTable(
                name: "ManagementReviewPolicies");

            migrationBuilder.DropTable(
                name: "OvertimeAllowanceApprovals");

            migrationBuilder.DropTable(
                name: "PasskeyCredentials");

            migrationBuilder.DropTable(
                name: "PayrollBatches");

            migrationBuilder.DropTable(
                name: "PayrollImportProfiles");

            migrationBuilder.DropTable(
                name: "PayrollLines");

            migrationBuilder.DropTable(
                name: "PersonnelProfiles");

            migrationBuilder.DropTable(
                name: "RateCalculations");

            migrationBuilder.DropTable(
                name: "TaskOrders");

            migrationBuilder.DropTable(
                name: "Tenants");

            migrationBuilder.DropTable(
                name: "TimeChargeOverrideApprovals");

            migrationBuilder.DropTable(
                name: "TimesheetApprovals");

            migrationBuilder.DropTable(
                name: "TimesheetDays");

            migrationBuilder.DropTable(
                name: "TimesheetExpenses");

            migrationBuilder.DropTable(
                name: "TimesheetLines");

            migrationBuilder.DropTable(
                name: "Timesheets");

            migrationBuilder.DropTable(
                name: "TimesheetVersions");

            migrationBuilder.DropTable(
                name: "TimesheetWorkNotes");

            migrationBuilder.DropTable(
                name: "UserNotifications");

            migrationBuilder.DropTable(
                name: "UserNotificationStates");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "WbsNodes");

            migrationBuilder.DropTable(
                name: "WeeklyStatusReports");

            migrationBuilder.DropTable(
                name: "WorkPeriodConfigurations");
        }
    }
}
