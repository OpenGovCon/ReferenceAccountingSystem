namespace GovConMoney.Domain.Entities;

public class ExternalServiceConfig : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string ServiceName { get; set; } = string.Empty;
    public string ApiKeyMasked { get; set; } = string.Empty;
    public string Endpoint { get; set; } = string.Empty;
}

