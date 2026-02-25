namespace GovConMoney.Domain.Enums;

public enum CostType
{
    Direct = 1,
    Indirect = 2,
    Unallowable = 3
}

public enum TimesheetStatus
{
    Draft = 1,
    Submitted = 2,
    Approved = 3,
    Corrected = 4
}

public enum TimesheetEntryType
{
    Work = 1,
    NoTime = 2,
    Pto = 3,
    Holiday = 4
}

public enum ExpenseStatus
{
    PendingApproval = 1,
    Approved = 2,
    Rejected = 3,
    Voided = 4
}

public enum ExpenseAccountingCategory
{
    Unassigned = 1,
    Allowable = 2,
    Unallowable = 3,
    GAndA = 4,
    Overhead = 5,
    Fringe = 6,
    Odc = 7,
    Material = 8
}

public enum EventType
{
    Create = 1,
    UpdateDraft = 2,
    Submit = 3,
    Approve = 4,
    Reject = 5,
    Correct = 6,
    Post = 7,
    Reverse = 8,
    DisableUser = 9,
    AssignmentChange = 10,
    SecurityLogin = 11,
    SecurityLogout = 12,
    MfaEnrollment = 13,
    PasskeyEnrollment = 14,
    RoleChange = 15,
    ContractPricingChange = 16,
    AccountingPeriodChange = 17,
    AllowabilityRuleChange = 18,
    SupervisorRelationshipChange = 19,
    OverrideApproval = 20,
    ChargeCodeLifecycleChange = 21,
    EnrollmentRequested = 22,
    EnrollmentApproved = 23,
    EnrollmentRejected = 24,
    ExpenseAccountingCategoryAssignment = 25,
    InternalAuditCycleChange = 26,
    InternalAuditAttestation = 27,
    ComplianceExceptionChange = 28,
    OvertimeApproval = 29,
    FuturePtoApproval = 30,
    FuturePtoApprovalRequest = 31
}

public enum AccountingPeriodStatus
{
    Open = 1,
    Closed = 2
}

public enum ContractType
{
    FixedValue = 1,
    Idiq = 2,
    CostPlusFee = 3
}

public enum LaborSite
{
    GovernmentSite = 1,
    ContractorSite = 2
}

public enum EnrollmentStatus
{
    Pending = 1,
    Approved = 2,
    Rejected = 3
}

public enum JournalEntryType
{
    Standard = 1,
    Payroll = 2,
    Burden = 3,
    Billing = 4,
    Adjusting = 5
}

public enum JournalEntryStatus
{
    Draft = 1,
    PendingApproval = 2,
    Approved = 3,
    Posted = 4,
    Reversed = 5
}

public enum BillingRunStatus
{
    Draft = 1,
    Approved = 2,
    Posted = 3
}

public enum InvoiceStatus
{
    Draft = 1,
    Approved = 2,
    Posted = 3
}

public enum RateCalculationReviewStatus
{
    NotRequired = 1,
    PendingManagerApproval = 2,
    Approved = 3,
    Rejected = 4
}

public enum AllocationBaseMethod
{
    PoolBaseCostTypeLaborDollars = 1,
    DirectLaborDollars = 2,
    DirectLaborHours = 3,
    TotalLaborHours = 4
}

public enum InternalAuditCycleStatus
{
    Draft = 1,
    PendingAttestation = 2,
    Submitted = 3,
    Approved = 4,
    Completed = 5,
    Closed = 6
}

public enum InternalAuditAttestationType
{
    Manager = 1,
    Compliance = 2
}

public enum InternalAuditReviewType
{
    ManagementReview = 1,
    InternalAudit = 2
}

public enum ComplianceChecklistResult
{
    Pass = 1,
    Fail = 2,
    NA = 3
}

public enum ComplianceExceptionSeverity
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum ComplianceExceptionCategory
{
    Timesheet = 1,
    Indirect = 2,
    Billing = 3,
    JE = 4,
    Close = 5,
    Reconciliation = 6
}

public enum ComplianceExceptionStatus
{
    Open = 1,
    Resolved = 2,
    AcceptedRisk = 3
}
