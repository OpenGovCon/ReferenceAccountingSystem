using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class Invoice : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid BillingRunId { get; set; }
    public Guid ContractId { get; set; }
    public string InvoiceNumber { get; set; } = string.Empty;
    public DateOnly PeriodStart { get; set; }
    public DateOnly PeriodEnd { get; set; }
    public InvoiceStatus Status { get; set; } = InvoiceStatus.Draft;
    public decimal TotalAmount { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid? PostedJournalEntryId { get; set; }
}
