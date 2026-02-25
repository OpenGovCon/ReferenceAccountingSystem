using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class AuditEvent : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string EntityType { get; init; } = string.Empty;
    public Guid EntityId { get; init; }
    public EventType EventType { get; init; }
    public Guid ActorUserId { get; init; }
    public string ActorRoles { get; init; } = string.Empty;
    public DateTime OccurredAtUtc { get; init; } = DateTime.UtcNow;
    public string? ReasonForChange { get; init; }
    public string? BeforeJson { get; init; }
    public string? AfterJson { get; init; }
    public string CorrelationId { get; init; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

