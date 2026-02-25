namespace GovConMoney.Domain.Entities;

public sealed class FuturePtoApprovalRequest : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid UserId { get; init; }
    public DateOnly WorkDate { get; init; }
    public Guid RequestedByUserId { get; init; }
    public string Reason { get; set; } = string.Empty;
    public DateTime RequestedAtUtc { get; set; }
}
