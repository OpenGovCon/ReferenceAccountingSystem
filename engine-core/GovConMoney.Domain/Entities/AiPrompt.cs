namespace GovConMoney.Domain.Entities;

public class AiPrompt : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string Function { get; set; } = "AccountantReporting";
    public string Prompt { get; set; } = string.Empty;
}

