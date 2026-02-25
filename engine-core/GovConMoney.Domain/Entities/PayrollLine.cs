namespace GovConMoney.Domain.Entities;

public class PayrollLine : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid PayrollBatchId { get; init; }
    public string EmployeeExternalId { get; init; } = string.Empty;
    public Guid? UserId { get; init; }
    public decimal LaborAmount { get; init; }
    public decimal FringeAmount { get; init; }
    public decimal TaxAmount { get; init; }
    public decimal OtherAmount { get; init; }
    public string? Notes { get; init; }
}
