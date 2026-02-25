using GovConMoney.Application.Abstractions;
using GovConMoney.Domain.Entities;

namespace GovConMoney.Application.Services;

public class NotificationService(
    IRepository repository,
    ITenantContext tenantContext,
    IClock clock)
{
    public UserNotification SendToUser(Guid userId, string title, string message, string category = "General")
    {
        var notification = CreateNotification(title, message, category);
        notification.TargetUserId = userId;
        repository.Add(notification);
        return notification;
    }

    public UserNotification SendToRole(string role, string title, string message, string category = "General")
    {
        var notification = CreateNotification(title, message, category);
        notification.TargetRole = role?.Trim();
        repository.Add(notification);
        return notification;
    }

    public UserNotification SendToTenant(string title, string message, string category = "General")
    {
        var notification = CreateNotification(title, message, category);
        repository.Add(notification);
        return notification;
    }

    public IReadOnlyList<UserNotification> GetInbox(bool includeRead = false, int take = 50)
    {
        var userId = tenantContext.UserId;
        var roles = tenantContext.Roles ?? Array.Empty<string>();
        var readIds = repository.Query<UserNotificationState>(tenantContext.TenantId)
            .Where(x => x.UserId == userId && x.IsRead)
            .Select(x => x.NotificationId)
            .ToHashSet();

        var notifications = repository.Query<UserNotification>(tenantContext.TenantId)
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(Math.Max(1, take * 2))
            .ToList()
            .Where(x =>
                (x.TargetUserId.HasValue && x.TargetUserId.Value == userId) ||
                (!string.IsNullOrWhiteSpace(x.TargetRole) && roles.Contains(x.TargetRole, StringComparer.OrdinalIgnoreCase)) ||
                (!x.TargetUserId.HasValue && string.IsNullOrWhiteSpace(x.TargetRole)))
            .ToList();

        if (!includeRead)
        {
            notifications = notifications.Where(x => !readIds.Contains(x.Id)).ToList();
        }

        return notifications
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(take)
            .ToList();
    }

    public void MarkRead(Guid notificationId)
    {
        var userId = tenantContext.UserId;
        var state = repository.Query<UserNotificationState>(tenantContext.TenantId)
            .SingleOrDefault(x => x.NotificationId == notificationId && x.UserId == userId);
        if (state is null)
        {
            state = new UserNotificationState
            {
                TenantId = tenantContext.TenantId,
                NotificationId = notificationId,
                UserId = userId,
                IsRead = true,
                ReadAtUtc = clock.UtcNow
            };
            repository.Add(state);
            return;
        }

        state.IsRead = true;
        state.ReadAtUtc = clock.UtcNow;
        repository.Update(state);
    }

    public void MarkAllRead()
    {
        foreach (var notification in GetInbox(includeRead: false, take: 500))
        {
            MarkRead(notification.Id);
        }
    }

    private UserNotification CreateNotification(string title, string message, string category)
    {
        return new UserNotification
        {
            TenantId = tenantContext.TenantId,
            Title = string.IsNullOrWhiteSpace(title) ? "Notification" : title.Trim(),
            Message = string.IsNullOrWhiteSpace(message) ? string.Empty : message.Trim(),
            Category = string.IsNullOrWhiteSpace(category) ? "General" : category.Trim(),
            CreatedByUserId = tenantContext.UserId,
            CreatedAtUtc = clock.UtcNow
        };
    }
}
