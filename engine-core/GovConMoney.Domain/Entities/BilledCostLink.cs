namespace GovConMoney.Domain.Entities;

public class BilledCostLink : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid InvoiceLineId { get; set; }
    public string SourceEntityType { get; set; } = string.Empty;
    public Guid SourceEntityId { get; set; }
    public decimal Amount { get; set; }
}
