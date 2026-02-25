using GovConMoney.Domain.Entities;
using GovConMoney.Infrastructure.Persistence;
using GovConMoney.Infrastructure.Security;

namespace GovConMoney.Infrastructure;

public sealed class PasskeyService(InMemoryDataStore store, TenantContextAccessor tenantContext)
{
    public object CreateRegistrationOptions()
    {
        return new
        {
            Challenge = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
            RpId = "localhost",
            UserId = tenantContext.UserId,
            TenantId = tenantContext.TenantId
        };
    }

    public PasskeyCredential CompleteRegistration(string credentialId, string publicKey, string transports, string aaguid)
    {
        var credential = new PasskeyCredential
        {
            TenantId = tenantContext.TenantId,
            UserId = tenantContext.UserId,
            CredentialId = credentialId,
            PublicKey = publicKey,
            SignCount = 0,
            Transports = transports,
            Aaguid = aaguid,
            CreatedAtUtc = DateTime.UtcNow
        };

        store.PasskeyCredentials.Add(credential);
        store.SaveChanges();
        return credential;
    }

    public bool ValidateAssertion(string credentialId)
    {
        return store.PasskeyCredentials.Any(x => x.TenantId == tenantContext.TenantId && x.CredentialId == credentialId);
    }
}
