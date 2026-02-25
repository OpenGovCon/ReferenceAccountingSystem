using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class InvoiceLine : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid InvoiceId { get; set; }
    public Guid ContractId { get; set; }
    public Guid TaskOrderId { get; set; }
    public Guid ClinId { get; set; }
    public Guid WbsNodeId { get; set; }
    public Guid ChargeCodeId { get; set; }
    public CostType CostType { get; set; }
    public string CostElement { get; set; } = string.Empty;
    public decimal Quantity { get; set; }
    public decimal Rate { get; set; }
    public decimal Amount { get; set; }
    public bool IsAllowable { get; set; }
    public string Description { get; set; } = string.Empty;
}
