namespace GovConMoney.Domain.Entities;

public class PersonnelProfile : ITenantScoped
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid TenantId { get; init; }
    public Guid UserId { get; init; }
    public Guid? SupervisorUserId { get; set; }
    public decimal HourlyRate { get; set; }
}

