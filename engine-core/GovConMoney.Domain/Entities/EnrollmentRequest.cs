using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class EnrollmentRequest : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public string UserName { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public string RequestedRole { get; init; } = "TimeReporter";
    public EnrollmentStatus Status { get; set; } = EnrollmentStatus.Pending;
    public DateTime SubmittedAtUtc { get; init; } = DateTime.UtcNow;
    public Guid? ReviewedByUserId { get; set; }
    public DateTime? ReviewedAtUtc { get; set; }
    public string? ReviewNote { get; set; }
}
