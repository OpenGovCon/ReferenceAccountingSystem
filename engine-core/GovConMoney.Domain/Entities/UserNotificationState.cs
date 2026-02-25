namespace GovConMoney.Domain.Entities;

public class UserNotificationState : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid NotificationId { get; init; }
    public Guid UserId { get; init; }
    public bool IsRead { get; set; }
    public DateTime? ReadAtUtc { get; set; }
}
