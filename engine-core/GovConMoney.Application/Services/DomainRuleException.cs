namespace GovConMoney.Application.Services;

public sealed class DomainRuleException(string message) : Exception(message);
