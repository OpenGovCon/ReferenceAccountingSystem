using GovConMoney.Domain.Enums;

namespace GovConMoney.Domain.Entities;

public class AccountingPeriod : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public DateOnly StartDate { get; init; }
    public DateOnly EndDate { get; init; }
    public AccountingPeriodStatus Status { get; set; }
}

