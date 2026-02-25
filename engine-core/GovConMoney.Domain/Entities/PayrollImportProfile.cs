namespace GovConMoney.Domain.Entities;

public class PayrollImportProfile : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string Name { get; set; } = string.Empty;
    public string SourceSystem { get; set; } = "Manual";
    public string Delimiter { get; set; } = ",";
    public bool HasHeaderRow { get; set; } = true;
    public string EmployeeExternalIdColumn { get; set; } = string.Empty;
    public string LaborAmountColumn { get; set; } = string.Empty;
    public string FringeAmountColumn { get; set; } = string.Empty;
    public string TaxAmountColumn { get; set; } = string.Empty;
    public string OtherAmountColumn { get; set; } = string.Empty;
    public string? NotesColumn { get; set; }
    public string? RequiredHeadersCsv { get; set; }
    public bool RequireKnownEmployeeExternalId { get; set; } = true;
    public bool DisallowDuplicateEmployeeExternalIds { get; set; } = true;
    public bool RequirePositiveLaborAmount { get; set; } = true;
    public bool IsActive { get; set; } = true;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid UpdatedByUserId { get; set; }
}
