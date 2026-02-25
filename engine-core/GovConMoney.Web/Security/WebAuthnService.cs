using Fido2NetLib;
using Fido2NetLib.Objects;
using GovConMoney.Domain.Entities;
using GovConMoney.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using System.Text;
using System.Reflection;

namespace GovConMoney.Web.Security;

public sealed class WebAuthnService(Fido2 fido2, IMemoryCache cache, InMemoryDataStore store)
{
    private static readonly TimeSpan ChallengeTtl = TimeSpan.FromMinutes(5);

    public (string FlowId, CredentialCreateOptions Options) BeginRegistration(Guid tenantId, Guid domainUserId, string userName)
    {
        var options = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                DisplayName = userName,
                Name = userName,
                Id = Encoding.UTF8.GetBytes(domainUserId.ToString())
            },
            AuthenticatorSelection = new AuthenticatorSelection
            {
                UserVerification = UserVerificationRequirement.Preferred,
                ResidentKey = ResidentKeyRequirement.Preferred
            },
            AttestationPreference = AttestationConveyancePreference.None,
            Extensions = new AuthenticationExtensionsClientInputs()
        });

        var flowId = Guid.NewGuid().ToString("N");
        cache.Set($"passkey-reg:{flowId}", new RegistrationState(tenantId, domainUserId, options), ChallengeTtl);
        return (flowId, options);
    }

    public async Task<PasskeyCredential> CompleteRegistrationAsync(string flowId, AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        if (!cache.TryGetValue<RegistrationState>($"passkey-reg:{flowId}", out var state) || state is null)
        {
            throw new InvalidOperationException("Passkey registration challenge expired or invalid.");
        }

        var credential = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = attestationResponse,
            OriginalOptions = state.Options,
            IsCredentialIdUniqueToUserCallback = (args, _) => Task.FromResult(!store.PasskeyCredentials.Any(x =>
                x.TenantId == state.TenantId &&
                x.CredentialId == Base64UrlTextEncoder.Encode(args.CredentialId)))
        }, cancellationToken);

        var saved = new PasskeyCredential
        {
            TenantId = state.TenantId,
            UserId = state.DomainUserId,
            CredentialId = attestationResponse.Id,
            PublicKey = Base64UrlTextEncoder.Encode(GetByteArray(credential, "PublicKey", "CredentialPublicKey")),
            SignCount = GetUInt32(credential, "SignCount", "Counter"),
            Transports = string.Empty,
            Aaguid = GetGuid(credential, "Aaguid", "AaGuid").ToString(),
            UserHandle = Base64UrlTextEncoder.Encode(Encoding.UTF8.GetBytes(state.DomainUserId.ToString()))
        };
        store.PasskeyCredentials.Add(saved);
        store.SaveChanges();
        cache.Remove($"passkey-reg:{flowId}");
        return saved;
    }

    public (string FlowId, AssertionOptions Options, Guid TenantId, Guid DomainUserId) BeginLogin(string username)
    {
        var normalizedUsername = username.Trim().ToUpperInvariant();
        var user = store.Users.SingleOrDefault(x => x.UserName.ToUpper() == normalizedUsername && !x.IsDisabled)
            ?? throw new InvalidOperationException("User not found.");

        var credentials = store.PasskeyCredentials
            .Where(x => x.TenantId == user.TenantId && x.UserId == user.Id)
            .Select(x => new PublicKeyCredentialDescriptor(Base64UrlTextEncoder.Decode(x.CredentialId)))
            .ToList();

        if (credentials.Count == 0)
        {
            throw new InvalidOperationException("No passkey is registered for this user.");
        }

        var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = credentials,
            UserVerification = UserVerificationRequirement.Preferred,
            Extensions = new AuthenticationExtensionsClientInputs()
        });

        var flowId = Guid.NewGuid().ToString("N");
        cache.Set($"passkey-login:{flowId}", new LoginState(user.TenantId, user.Id, options), ChallengeTtl);
        return (flowId, options, user.TenantId, user.Id);
    }

    public async Task<(Guid TenantId, Guid DomainUserId)> CompleteLoginAsync(string flowId, AuthenticatorAssertionRawResponse assertionResponse, CancellationToken cancellationToken)
    {
        if (!cache.TryGetValue<LoginState>($"passkey-login:{flowId}", out var state) || state is null)
        {
            throw new InvalidOperationException("Passkey login challenge expired or invalid.");
        }

        var credentialId = assertionResponse.Id;
        var storedCredential = store.PasskeyCredentials.SingleOrDefault(x =>
            x.TenantId == state.TenantId &&
            x.UserId == state.DomainUserId &&
            x.CredentialId == credentialId)
            ?? throw new InvalidOperationException("Passkey credential not found.");

        var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = state.Options,
            StoredPublicKey = Base64UrlTextEncoder.Decode(storedCredential.PublicKey),
            StoredSignatureCounter = storedCredential.SignCount,
            IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
            {
                if (args.UserHandle is null || args.UserHandle.Length == 0)
                {
                    return Task.FromResult(true);
                }

                var userHandle = Base64UrlTextEncoder.Encode(args.UserHandle);
                return Task.FromResult(string.Equals(userHandle, storedCredential.UserHandle, StringComparison.Ordinal));
            }
        }, cancellationToken);

        storedCredential.SignCount = GetUInt32(result, "SignCount", "Counter");
        store.SaveChanges();
        cache.Remove($"passkey-login:{flowId}");
        return (state.TenantId, state.DomainUserId);
    }

    private static byte[] GetByteArray(object source, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            var value = source.GetType().GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance)?.GetValue(source);
            if (value is byte[] bytes && bytes.Length > 0)
            {
                return bytes;
            }
        }

        throw new InvalidOperationException($"Unable to resolve byte[] property from {source.GetType().Name}.");
    }

    private static uint GetUInt32(object source, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            var value = source.GetType().GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance)?.GetValue(source);
            if (value is uint uintValue)
            {
                return uintValue;
            }
            if (value is int intValue && intValue >= 0)
            {
                return (uint)intValue;
            }
        }

        return 0;
    }

    private static Guid GetGuid(object source, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            var value = source.GetType().GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance)?.GetValue(source);
            if (value is Guid guid)
            {
                return guid;
            }
        }

        return Guid.Empty;
    }

    private sealed record RegistrationState(Guid TenantId, Guid DomainUserId, CredentialCreateOptions Options);
    private sealed record LoginState(Guid TenantId, Guid DomainUserId, AssertionOptions Options);
}
