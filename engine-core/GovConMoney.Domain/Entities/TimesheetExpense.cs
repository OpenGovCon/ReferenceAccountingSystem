using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class TimesheetExpense : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid TimesheetId { get; init; }
    public DateOnly ExpenseDate { get; set; }
    public Guid ChargeCodeId { get; set; }
    public CostType CostType { get; set; }
    public decimal Amount { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ExpenseAccountingCategory AccountingCategory { get; set; } = ExpenseAccountingCategory.Unassigned;
    public Guid? AccountingCategoryAssignedByUserId { get; set; }
    public DateTime? AccountingCategoryAssignedAtUtc { get; set; }
    public ExpenseStatus Status { get; set; } = ExpenseStatus.PendingApproval;
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public string? RejectionReason { get; set; }
    public Guid? VoidedByUserId { get; set; }
    public DateTime? VoidedAtUtc { get; set; }
    public string? VoidReason { get; set; }
}
