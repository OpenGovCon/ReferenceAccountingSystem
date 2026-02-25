using Fido2NetLib;
using Fido2NetLib.Objects;
using GovConMoney.Application.Models;
using GovConMoney.Application.Abstractions;
using GovConMoney.Application.Services;
using GovConMoney.Domain.Entities;
using GovConMoney.Domain.Enums;
using GovConMoney.Infrastructure;
using GovConMoney.Infrastructure.Persistence;
using GovConMoney.Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using GovConMoney.Web.Security;
using GovConMoney.Web.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
var primaryConnection = builder.Configuration.GetConnectionString("Primary")
    ?? "Server=.\\SQLEXPRESS;Database=GovConMoney;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True;";
var identityConnection = builder.Configuration.GetConnectionString("Identity")
    ?? "Server=.\\SQLEXPRESS;Database=GovConMoneyIdentity;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True;";
builder.Services.AddDbContext<GovConMoneyDbContext>(options =>
    options.UseSqlServer(primaryConnection, sql =>
        sql.MigrationsAssembly("GovConMoney.Web")));
builder.Services.AddDbContext<GovConIdentityDbContext>(options =>
    options.UseSqlServer(identityConnection));
builder.Services.AddIdentity<GovConIdentityUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 10;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.MaxFailedAccessAttempts = 5;
    })
    .AddEntityFrameworkStores<GovConIdentityDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();
builder.Services.ConfigureApplicationCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.LoginPath = "/auth/login";
        options.AccessDeniedPath = "/auth/login?error=denied";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdmin", p => p.RequireRole("Admin"));
    options.AddPolicy("RequireCompliance", p => p.RequireRole("Compliance"));
    options.AddPolicy("RequireTimeReporter", p => p.RequireRole("TimeReporter"));
    options.AddPolicy("RequireAccountant", p => p.RequireRole("Accountant"));
    options.AddPolicy("RequireSupervisor", p => p.RequireRole("Supervisor"));
    options.AddPolicy("RequireManager", p => p.RequireRole("Manager"));
    options.AddPolicy("RequireManagerOrAccountant", p => p.RequireRole("Manager", "Accountant"));
    options.AddPolicy("RequireComplianceManagerOrAccountant", p => p.RequireRole("Compliance", "Manager", "Accountant"));
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("auth", limiterOptions =>
    {
        limiterOptions.PermitLimit = 10;
        limiterOptions.Window = TimeSpan.FromMinutes(1);
        limiterOptions.QueueLimit = 0;
        limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });
});

builder.Services.AddGovConMoney();
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<PayrollImportPreviewStore>();
builder.Services.AddHostedService<MonthlyCloseComplianceHostedService>();
builder.Services.AddSingleton(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var origins = config.GetSection("Fido2:Origins").Get<string[]>()?
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .ToHashSet(StringComparer.OrdinalIgnoreCase)
        ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "https://localhost:7289",
            "https://localhost:5001"
        };

    var rpId = config["Fido2:RelyingPartyId"] ?? "localhost";
    var rpName = config["Fido2:RelyingPartyName"] ?? "GovConMoney";

    return new Fido2(new Fido2Configuration
    {
        ServerDomain = rpId,
        ServerName = rpName,
        Origins = origins
    });
});
builder.Services.AddScoped<WebAuthnService>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<GovConMoneyDbContext>();
    DbMigrationBootstrapper.ApplyMigrationsWithLegacyBaseline(db);

    var identityDb = scope.ServiceProvider.GetRequiredService<GovConIdentityDbContext>();
    identityDb.Database.EnsureCreated();

    var store = scope.ServiceProvider.GetRequiredService<InMemoryDataStore>();
    SeedData.Initialize(store);
    await IdentitySeed.InitializeAsync(scope.ServiceProvider);
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.UseRateLimiter();

app.Use(async (httpContext, next) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
    {
        await next();
        return;
    }

    var requireMfa = httpContext.RequestServices.GetRequiredService<IConfiguration>().GetValue<bool>("Security:RequireMfa", true);
    if (!requireMfa)
    {
        await next();
        return;
    }

    var path = httpContext.Request.Path.Value ?? string.Empty;
    var hasFileExtension = Path.HasExtension(path);
    if (hasFileExtension ||
        path.StartsWith("/_framework", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/_content", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/_blazor", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }

    var allowedPaths = new[]
    {
        "/security/mfa-enroll",
        "/security/passkeys",
        "/api/auth/mfa/setup-form",
        "/api/auth/mfa/enable-form",
        "/logout"
    };
    if (allowedPaths.Any(prefix => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
    {
        await next();
        return;
    }

    var userManager = httpContext.RequestServices.GetRequiredService<UserManager<GovConIdentityUser>>();
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null || user.TwoFactorEnabled)
    {
        await next();
        return;
    }

    if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
    {
        httpContext.Response.StatusCode = StatusCodes.Status403Forbidden;
        await httpContext.Response.WriteAsJsonAsync(new { error = "mfa_setup_required" });
        return;
    }

    httpContext.Response.Redirect("/security/mfa-enroll?first=1");
});

app.MapStaticAssets();

app.MapPost("/api/login-form", async (HttpContext httpContext, SignInManager<GovConIdentityUser> signInManager, UserManager<GovConIdentityUser> userManager, InMemoryDataStore store, IAuditService audit, IConfiguration config) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var username = form["username"].ToString().Trim();
    var password = form["password"].ToString();
    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
    {
        return Results.Redirect("/auth/login?error=missing_credentials");
    }

    var user = await userManager.FindByNameAsync(username);
    if (user is null)
    {
        return Results.Redirect("/auth/login?error=invalid_credentials");
    }

    var signInResult = await signInManager.PasswordSignInAsync(user, password, isPersistent: false, lockoutOnFailure: true);
    if (signInResult.RequiresTwoFactor)
    {
        return Results.Redirect("/auth/mfa");
    }

    if (!signInResult.Succeeded)
    {
        return Results.Redirect("/auth/login?error=invalid_credentials");
    }

    if (config.GetValue<bool>("Security:RequireMfa", true) && !user.TwoFactorEnabled)
    {
        return Results.Redirect("/security/mfa-enroll?first=1");
    }

    var roles = await userManager.GetRolesAsync(user);
    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "Security",
        EntityId = user.DomainUserId,
        EventType = EventType.SecurityLogin,
        ActorUserId = user.DomainUserId,
        ActorRoles = string.Join(',', roles),
        OccurredAtUtc = DateTime.UtcNow,
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    if (config.GetValue<bool>("Security:RequirePasskeyEnrollment", false) &&
        !store.PasskeyCredentials.Any(x => x.TenantId == user.TenantId && x.UserId == user.DomainUserId))
    {
        return Results.Redirect("/security/passkeys?required=1");
    }

    return Results.Redirect("/home");
}).RequireRateLimiting("auth");

app.MapPost("/api/login-mfa-form", async (HttpContext httpContext, SignInManager<GovConIdentityUser> signInManager, UserManager<GovConIdentityUser> userManager, IAuditService audit, IConfiguration config, InMemoryDataStore store) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var code = form["code"].ToString().Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal);
    var rememberMachine = bool.TryParse(form["rememberMachine"], out var parsedRemember) && parsedRemember;

    var result = await signInManager.TwoFactorAuthenticatorSignInAsync(code, false, rememberMachine);
    if (!result.Succeeded)
    {
        return Results.Redirect("/auth/mfa?error=invalid_code");
    }

    var user = await signInManager.GetTwoFactorAuthenticationUserAsync() ?? await signInManager.UserManager.GetUserAsync(httpContext.User);
    if (user is null)
    {
        return Results.Redirect("/auth/login");
    }

    if (config.GetValue<bool>("Security:RequireMfa", true) && !user.TwoFactorEnabled)
    {
        await signInManager.SignOutAsync();
        return Results.Redirect("/auth/login?error=mfa_required");
    }

    var roles = await userManager.GetRolesAsync(user);
    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "Security",
        EntityId = user.DomainUserId,
        EventType = EventType.SecurityLogin,
        ActorUserId = user.DomainUserId,
        ActorRoles = string.Join(',', roles),
        OccurredAtUtc = DateTime.UtcNow,
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    if (config.GetValue<bool>("Security:RequirePasskeyEnrollment", false) &&
        !store.PasskeyCredentials.Any(x => x.TenantId == user.TenantId && x.UserId == user.DomainUserId))
    {
        return Results.Redirect("/security/passkeys?required=1");
    }

    return Results.Redirect("/home");
}).RequireRateLimiting("auth");

app.MapPost("/api/login", async (string username, string password, SignInManager<GovConIdentityUser> signInManager, UserManager<GovConIdentityUser> userManager, InMemoryDataStore store, IAuditService audit, IConfiguration config) =>
{
    var user = await userManager.FindByNameAsync(username);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    var result = await signInManager.PasswordSignInAsync(user, password, isPersistent: false, lockoutOnFailure: true);
    if (result.RequiresTwoFactor)
    {
        return Results.Ok(new { requiresTwoFactor = true });
    }

    if (!result.Succeeded)
    {
        return Results.Unauthorized();
    }

    if (config.GetValue<bool>("Security:RequireMfa", true) && !user.TwoFactorEnabled)
    {
        return Results.Ok(new { user = user.UserName, requiresMfaSetup = true, mfaSetupUrl = "/security/mfa-enroll?first=1" });
    }

    var roles = await userManager.GetRolesAsync(user);
    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "Security",
        EntityId = user.DomainUserId,
        EventType = EventType.SecurityLogin,
        ActorUserId = user.DomainUserId,
        ActorRoles = string.Join(',', roles),
        OccurredAtUtc = DateTime.UtcNow,
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    if (config.GetValue<bool>("Security:RequirePasskeyEnrollment", false) &&
        !store.PasskeyCredentials.Any(x => x.TenantId == user.TenantId && x.UserId == user.DomainUserId))
    {
        return Results.Ok(new { user = user.UserName, requiresPasskeyEnrollment = true });
    }

    return Results.Ok(new { user = user.UserName });
}).RequireRateLimiting("auth");

app.MapPost("/logout", async (HttpContext httpContext, SignInManager<GovConIdentityUser> signInManager, IAuditService audit) =>
{
    var tenantId = Guid.TryParse(httpContext.User.FindFirstValue("tenant_id"), out var parsedTenant) ? parsedTenant : Guid.Empty;
    var actorId = Guid.TryParse(httpContext.User.FindFirstValue("domain_user_id"), out var parsedActor) ? parsedActor : Guid.Empty;
    var actorRoles = string.Join(',', httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value));

    if (tenantId != Guid.Empty && actorId != Guid.Empty)
    {
        audit.Record(new AuditEvent
        {
            TenantId = tenantId,
            EntityType = "Security",
            EntityId = actorId,
            EventType = EventType.SecurityLogout,
            ActorUserId = actorId,
            ActorRoles = actorRoles,
            OccurredAtUtc = DateTime.UtcNow,
            CorrelationId = Guid.NewGuid().ToString("N")
        });
    }

    await signInManager.SignOutAsync();
    return Results.Redirect("/auth/login");
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/mfa/setup-form", [Authorize] async (HttpContext httpContext, UserManager<GovConIdentityUser> userManager) =>
{
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null)
    {
        return Results.Redirect("/auth/login");
    }

    await userManager.ResetAuthenticatorKeyAsync(user);
    var key = await userManager.GetAuthenticatorKeyAsync(user) ?? string.Empty;
    var issuer = Uri.EscapeDataString("GovConMoney");
    var account = Uri.EscapeDataString(user.Email ?? user.UserName ?? user.Id);
    var otpUri = $"otpauth://totp/{issuer}:{account}?secret={key}&issuer={issuer}&digits=6";

    return Results.Redirect($"/security/passkeys?mfaKey={Uri.EscapeDataString(key)}&mfaUri={Uri.EscapeDataString(otpUri)}");
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/mfa/enable-form", [Authorize] async (HttpContext httpContext, UserManager<GovConIdentityUser> userManager, InMemoryDataStore store, IAuditService audit) =>
{
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null)
    {
        return Results.Redirect("/auth/login");
    }

    var form = await httpContext.Request.ReadFormAsync();
    var code = form["code"].ToString().Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal);
    var isValid = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, code);
    if (!isValid)
    {
        return Results.Redirect("/security/passkeys?error=invalid_mfa_code");
    }

    await userManager.SetTwoFactorEnabledAsync(user, true);
    var appUser = store.Users.SingleOrDefault(x => x.Id == user.DomainUserId);
    if (appUser is not null)
    {
        appUser.MfaEnabled = true;
        store.SaveChanges();
    }

    var roles = await userManager.GetRolesAsync(user);
    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "Security",
        EntityId = user.DomainUserId,
        EventType = EventType.MfaEnrollment,
        ActorUserId = user.DomainUserId,
        ActorRoles = string.Join(',', roles),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = "User enabled authenticator MFA.",
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    return Results.Redirect("/security/passkeys?mfaEnabled=1");
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/enroll-form", async (HttpContext httpContext, InMemoryDataStore store) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["tenantId"], out var tenantId))
    {
        return Results.Redirect("/auth/enroll?error=invalid_tenant");
    }

    var username = form["username"].ToString().Trim();
    var email = form["email"].ToString().Trim();
    var requestedRole = form["requestedRole"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email))
    {
        return Results.Redirect("/auth/enroll?error=missing_fields");
    }

    if (!store.Tenants.Any(x => x.Id == tenantId))
    {
        return Results.Redirect("/auth/enroll?error=invalid_tenant");
    }

    var normalizedUserName = username.ToUpperInvariant();
    if (store.Users.Any(x => x.TenantId == tenantId && x.UserName.ToUpper() == normalizedUserName))
    {
        return Results.Redirect("/auth/enroll?error=user_exists");
    }

    var enrollment = new GovConMoney.Domain.Entities.EnrollmentRequest
    {
        TenantId = tenantId,
        UserName = username,
        Email = email,
        RequestedRole = string.IsNullOrWhiteSpace(requestedRole) ? "TimeReporter" : requestedRole,
        Status = EnrollmentStatus.Pending,
        SubmittedAtUtc = DateTime.UtcNow
    };
    store.EnrollmentRequests.Add(enrollment);
    store.AuditEvents.Add(new GovConMoney.Domain.Entities.AuditEvent
    {
        TenantId = tenantId,
        EntityType = "EnrollmentRequest",
        EntityId = enrollment.Id,
        EventType = EventType.EnrollmentRequested,
        ActorUserId = Guid.Empty,
        ActorRoles = "Anonymous",
        OccurredAtUtc = DateTime.UtcNow,
        AfterJson = System.Text.Json.JsonSerializer.Serialize(enrollment),
        CorrelationId = Guid.NewGuid().ToString("N")
    });
    store.SaveChanges();

    return Results.Redirect("/auth/enroll?submitted=1");
}).RequireRateLimiting("auth");

app.MapPost("/api/admin/enrollments/{requestId:guid}/approve-form", [Authorize(Policy = "RequireAdmin")] async (
    Guid requestId,
    HttpContext httpContext,
    InMemoryDataStore store,
    UserManager<GovConIdentityUser> userManager,
    RoleManager<IdentityRole> roleManager) =>
{
    var request = store.EnrollmentRequests.SingleOrDefault(x => x.Id == requestId)
        ?? throw new InvalidOperationException("Enrollment request not found.");
    if (request.Status != EnrollmentStatus.Pending)
    {
        return Results.Redirect("/admin/enrollments");
    }

    var actorId = Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedActorId)
        ? parsedActorId
        : Guid.Empty;

    var role = request.RequestedRole;
    var allowedRoles = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "TimeReporter", "Supervisor", "Accountant", "Compliance", "Manager" };
    if (!allowedRoles.Contains(role))
    {
        role = "TimeReporter";
    }

    var newUser = new GovConMoney.Domain.Entities.AppUser
    {
        TenantId = request.TenantId,
        UserName = request.UserName,
        Email = request.Email,
        EmployeeExternalId = $"EMP-{Math.Abs(request.UserName.GetHashCode()) % 100000:D5}",
        MfaEnabled = false,
        PasskeyRequired = false
    };
    newUser.Roles.Add(role);
    store.Users.Add(newUser);

    if (!await roleManager.RoleExistsAsync(role))
    {
        var createRole = await roleManager.CreateAsync(new IdentityRole(role));
        if (!createRole.Succeeded)
        {
            throw new InvalidOperationException($"Failed to create role {role}: {string.Join(", ", createRole.Errors.Select(x => x.Description))}");
        }
    }

    var identityUser = new GovConIdentityUser
    {
        Id = newUser.Id.ToString(),
        DomainUserId = newUser.Id,
        TenantId = newUser.TenantId,
        UserName = newUser.UserName,
        Email = newUser.Email,
        EmailConfirmed = true,
        LockoutEnabled = true,
        PasskeyRequired = false
    };
    var createUserResult = await userManager.CreateAsync(identityUser, IdentitySeed.SeedPassword);
    if (!createUserResult.Succeeded)
    {
        throw new InvalidOperationException($"Failed to create identity user for enrollment: {string.Join(", ", createUserResult.Errors.Select(x => x.Description))}");
    }

    var addRoleResult = await userManager.AddToRoleAsync(identityUser, role);
    if (!addRoleResult.Succeeded)
    {
        throw new InvalidOperationException($"Failed to assign role to identity user: {string.Join(", ", addRoleResult.Errors.Select(x => x.Description))}");
    }

    await userManager.AddClaimsAsync(identityUser,
    [
        new Claim("tenant_id", newUser.TenantId.ToString()),
        new Claim("domain_user_id", newUser.Id.ToString()),
        new Claim("passkey_required", "false")
    ]);

    store.PersonnelProfiles.Add(new GovConMoney.Domain.Entities.PersonnelProfile
    {
        TenantId = request.TenantId,
        UserId = newUser.Id,
        HourlyRate = 0m
    });

    request.Status = EnrollmentStatus.Approved;
    request.ReviewedByUserId = actorId;
    request.ReviewedAtUtc = DateTime.UtcNow;
    request.ReviewNote = "Approved by admin.";

    store.AuditEvents.Add(new GovConMoney.Domain.Entities.AuditEvent
    {
        TenantId = request.TenantId,
        EntityType = "EnrollmentRequest",
        EntityId = request.Id,
        EventType = EventType.EnrollmentApproved,
        ActorUserId = actorId,
        ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
        OccurredAtUtc = DateTime.UtcNow,
        AfterJson = System.Text.Json.JsonSerializer.Serialize(request),
        CorrelationId = Guid.NewGuid().ToString("N")
    });
    store.AuditEvents.Add(new GovConMoney.Domain.Entities.AuditEvent
    {
        TenantId = request.TenantId,
        EntityType = "UserRole",
        EntityId = newUser.Id,
        EventType = EventType.RoleChange,
        ActorUserId = actorId,
        ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = $"Role assigned during enrollment approval: {role}",
        AfterJson = JsonSerializer.Serialize(new { userId = newUser.Id, role }),
        CorrelationId = Guid.NewGuid().ToString("N")
    });
    store.SaveChanges();

    return Results.Redirect("/admin/enrollments");
});

app.MapPost("/api/admin/enrollments/{requestId:guid}/reject-form", [Authorize(Policy = "RequireAdmin")] (Guid requestId, HttpContext httpContext, InMemoryDataStore store) =>
{
    var request = store.EnrollmentRequests.SingleOrDefault(x => x.Id == requestId)
        ?? throw new InvalidOperationException("Enrollment request not found.");
    if (request.Status != EnrollmentStatus.Pending)
    {
        return Results.Redirect("/admin/enrollments");
    }

    var actorId = Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedActorId)
        ? parsedActorId
        : Guid.Empty;

    request.Status = EnrollmentStatus.Rejected;
    request.ReviewedByUserId = actorId;
    request.ReviewedAtUtc = DateTime.UtcNow;
    request.ReviewNote = "Rejected by admin.";

    store.AuditEvents.Add(new GovConMoney.Domain.Entities.AuditEvent
    {
        TenantId = request.TenantId,
        EntityType = "EnrollmentRequest",
        EntityId = request.Id,
        EventType = EventType.EnrollmentRejected,
        ActorUserId = actorId,
        ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
        OccurredAtUtc = DateTime.UtcNow,
        AfterJson = System.Text.Json.JsonSerializer.Serialize(request),
        CorrelationId = Guid.NewGuid().ToString("N")
    });
    store.SaveChanges();

    return Results.Redirect("/admin/enrollments");
});

app.MapPost("/api/admin/work-period/set-form", [Authorize(Policy = "RequireAdmin")] async (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Redirect("/admin/security?error=tenant");
    }

    var form = await httpContext.Request.ReadFormAsync();
    if (!int.TryParse(form["weekStartDay"], out var weekStartDay))
    {
        return Results.Redirect("/admin/security?error=invalid_work_period");
    }

    var periodLengthDays = int.TryParse(form["periodLengthDays"], out var parsedPeriodLengthDays) ? parsedPeriodLengthDays : 7;
    periodLengthDays = Math.Clamp(periodLengthDays, 1, 14);
    var dailyEntryRequired = ParseCheckbox(form, "dailyEntryRequired");
    var dailyEntryGraceDays = int.TryParse(form["dailyEntryGraceDays"], out var parsedGraceDays) ? parsedGraceDays : 1;
    dailyEntryGraceDays = Math.Clamp(dailyEntryGraceDays, 0, 14);
    var dailyEntryHardFail = ParseCheckbox(form, "dailyEntryHardFail");
    var dailyEntryIncludeWeekends = ParseCheckbox(form, "dailyEntryIncludeWeekends");

    weekStartDay = ((weekStartDay % 7) + 7) % 7;
    var config = store.WorkPeriodConfigurations.SingleOrDefault(x => x.TenantId == tenantId);
    if (config is null)
    {
        config = new WorkPeriodConfiguration
        {
            TenantId = tenantId,
            WeekStartDay = weekStartDay,
            PeriodLengthDays = periodLengthDays,
            DailyEntryRequired = dailyEntryRequired,
            DailyEntryGraceDays = dailyEntryGraceDays,
            DailyEntryHardFail = dailyEntryHardFail,
            DailyEntryIncludeWeekends = dailyEntryIncludeWeekends,
            UpdatedAtUtc = DateTime.UtcNow
        };
        store.WorkPeriodConfigurations.Add(config);
    }
    else
    {
        config.WeekStartDay = weekStartDay;
        config.PeriodLengthDays = periodLengthDays;
        config.DailyEntryRequired = dailyEntryRequired;
        config.DailyEntryGraceDays = dailyEntryGraceDays;
        config.DailyEntryHardFail = dailyEntryHardFail;
        config.DailyEntryIncludeWeekends = dailyEntryIncludeWeekends;
        config.UpdatedAtUtc = DateTime.UtcNow;
    }

    store.SaveChanges();
    return Results.Redirect("/admin/security?saved=1");
});

app.MapPost("/api/admin/management-review-policy/set-form", [Authorize(Policy = "RequireAdmin")] async (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Redirect("/admin/security?error=tenant");
    }

    var form = await httpContext.Request.ReadFormAsync();
    var actorId = Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedActorId)
        ? parsedActorId
        : (Guid?)null;
    var policy = store.ManagementReviewPolicies.SingleOrDefault(x => x.TenantId == tenantId);
    var requireBillingManager = form.ContainsKey("requireManagerApprovalForBillingAboveThreshold")
        ? ParseCheckbox(form, "requireManagerApprovalForBillingAboveThreshold")
        : (policy?.RequireManagerApprovalForBillingAboveThreshold ?? true);
    var requireAdjustingManager = form.ContainsKey("requireManagerCoSignForAdjustingAboveThreshold")
        ? ParseCheckbox(form, "requireManagerCoSignForAdjustingAboveThreshold")
        : (policy?.RequireManagerCoSignForAdjustingAboveThreshold ?? true);
    var enablePeriodicInternalAudit = form.ContainsKey("enablePeriodicInternalAuditAttestation")
        ? ParseCheckbox(form, "enablePeriodicInternalAuditAttestation")
        : (policy?.EnablePeriodicInternalAuditAttestation ?? true);
    var requireManagerAuditAttestation = form.ContainsKey("requireManagerInternalAuditAttestation")
        ? ParseCheckbox(form, "requireManagerInternalAuditAttestation")
        : (policy?.RequireManagerInternalAuditAttestation ?? true);
    var requireComplianceAuditAttestation = form.ContainsKey("requireComplianceInternalAuditAttestation")
        ? ParseCheckbox(form, "requireComplianceInternalAuditAttestation")
        : (policy?.RequireComplianceInternalAuditAttestation ?? true);
    var billingThreshold = decimal.TryParse(form["billingManagerApprovalThreshold"], out var parsedBillingThreshold)
        ? parsedBillingThreshold
        : (policy?.BillingManagerApprovalThreshold ?? 50000m);
    var adjustingThreshold = decimal.TryParse(form["adjustingManagerCoSignThreshold"], out var parsedAdjustingThreshold)
        ? parsedAdjustingThreshold
        : (policy?.AdjustingManagerCoSignThreshold ?? 10000m);
    var internalAuditCadenceDays = int.TryParse(form["internalAuditCadenceDays"], out var parsedCadenceDays)
        ? parsedCadenceDays
        : (policy?.InternalAuditCadenceDays ?? 30);
    var internalAuditDueDays = int.TryParse(form["internalAuditDueDaysAfterPeriodEnd"], out var parsedDueDays)
        ? parsedDueDays
        : (policy?.InternalAuditDueDaysAfterPeriodEnd ?? 10);
    billingThreshold = Math.Max(0m, Math.Round(billingThreshold, 2));
    adjustingThreshold = Math.Max(0m, Math.Round(adjustingThreshold, 2));
    internalAuditCadenceDays = Math.Clamp(internalAuditCadenceDays, 1, 365);
    internalAuditDueDays = Math.Clamp(internalAuditDueDays, 0, 120);

    if (policy is null)
    {
        policy = new ManagementReviewPolicy
        {
            TenantId = tenantId,
            RequireManagerApprovalForBillingAboveThreshold = requireBillingManager,
            BillingManagerApprovalThreshold = billingThreshold,
            RequireManagerCoSignForAdjustingAboveThreshold = requireAdjustingManager,
            AdjustingManagerCoSignThreshold = adjustingThreshold,
            EnablePeriodicInternalAuditAttestation = enablePeriodicInternalAudit,
            InternalAuditCadenceDays = internalAuditCadenceDays,
            InternalAuditDueDaysAfterPeriodEnd = internalAuditDueDays,
            RequireManagerInternalAuditAttestation = requireManagerAuditAttestation,
            RequireComplianceInternalAuditAttestation = requireComplianceAuditAttestation,
            UpdatedAtUtc = DateTime.UtcNow,
            UpdatedByUserId = actorId
        };
        store.ManagementReviewPolicies.Add(policy);
    }
    else
    {
        policy.RequireManagerApprovalForBillingAboveThreshold = requireBillingManager;
        policy.BillingManagerApprovalThreshold = billingThreshold;
        policy.RequireManagerCoSignForAdjustingAboveThreshold = requireAdjustingManager;
        policy.AdjustingManagerCoSignThreshold = adjustingThreshold;
        policy.EnablePeriodicInternalAuditAttestation = enablePeriodicInternalAudit;
        policy.InternalAuditCadenceDays = internalAuditCadenceDays;
        policy.InternalAuditDueDaysAfterPeriodEnd = internalAuditDueDays;
        policy.RequireManagerInternalAuditAttestation = requireManagerAuditAttestation;
        policy.RequireComplianceInternalAuditAttestation = requireComplianceAuditAttestation;
        policy.UpdatedAtUtc = DateTime.UtcNow;
        policy.UpdatedByUserId = actorId;
    }

    store.SaveChanges();
    return Results.Redirect("/admin/security?managementSaved=1");
});

static bool ParseCheckbox(IFormCollection form, string key)
{
    if (!form.TryGetValue(key, out var value))
    {
        return false;
    }

    var raw = value.ToString();
    return string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
        || string.Equals(raw, "on", StringComparison.OrdinalIgnoreCase)
        || string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase);
}

app.MapPost("/api/passkeys/register/options", [Authorize] async (
    HttpContext httpContext,
    UserManager<GovConIdentityUser> userManager,
    WebAuthnService passkeys) =>
{
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    var (flowId, options) = passkeys.BeginRegistration(user.TenantId, user.DomainUserId, user.UserName ?? user.Id);
    return Results.Json(new { flowId, options });
}).RequireRateLimiting("auth");
app.MapPost("/api/passkeys/register/complete", [Authorize] async (
    PasskeyRegisterCompleteRequest request,
    WebAuthnService passkeys,
    UserManager<GovConIdentityUser> userManager,
    HttpContext httpContext,
    IAuditService audit,
    CancellationToken cancellationToken) =>
{
    var user = await userManager.GetUserAsync(httpContext.User);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    await passkeys.CompleteRegistrationAsync(request.FlowId, request.Attestation, cancellationToken);
    user.PasskeyRequired = true;
    await userManager.UpdateAsync(user);
    var roles = await userManager.GetRolesAsync(user);
    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "Security",
        EntityId = user.DomainUserId,
        EventType = EventType.PasskeyEnrollment,
        ActorUserId = user.DomainUserId,
        ActorRoles = string.Join(',', roles),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = "User enrolled a passkey.",
        CorrelationId = Guid.NewGuid().ToString("N")
    });
    return Results.Ok(new { success = true });
}).RequireRateLimiting("auth");
app.MapPost("/api/passkeys/login/options", async (
    PasskeyLoginOptionsRequest request,
    WebAuthnService passkeys) =>
{
    if (string.IsNullOrWhiteSpace(request.Username))
    {
        return Results.BadRequest(new { error = "username is required" });
    }

    var (flowId, options, _, _) = passkeys.BeginLogin(request.Username);
    return Results.Json(new { flowId, options });
}).RequireRateLimiting("auth");
app.MapPost("/api/passkeys/login/complete", async (
    PasskeyLoginCompleteRequest request,
    WebAuthnService passkeys,
    SignInManager<GovConIdentityUser> signInManager,
    UserManager<GovConIdentityUser> userManager,
    IConfiguration config,
    IAuditService audit,
    CancellationToken cancellationToken) =>
{
    var (_, domainUserId) = await passkeys.CompleteLoginAsync(request.FlowId, request.Assertion, cancellationToken);
    var identityUser = await userManager.FindByIdAsync(domainUserId.ToString());
    if (identityUser is null)
    {
        return Results.Unauthorized();
    }

    if (config.GetValue<bool>("Security:RequireMfa", true) && !identityUser.TwoFactorEnabled)
    {
        return Results.BadRequest(new { error = "mfa_required" });
    }

    await signInManager.SignInAsync(identityUser, false);
    var roles = await userManager.GetRolesAsync(identityUser);
    audit.Record(new AuditEvent
    {
        TenantId = identityUser.TenantId,
        EntityType = "Security",
        EntityId = identityUser.DomainUserId,
        EventType = EventType.SecurityLogin,
        ActorUserId = identityUser.DomainUserId,
        ActorRoles = string.Join(',', roles),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = "Passkey login completed.",
        CorrelationId = Guid.NewGuid().ToString("N")
    });
    return Results.Ok(new { success = true });
}).RequireRateLimiting("auth");

app.MapPost("/api/compliance/contracts", [Authorize(Policy = "RequireCompliance")] (string contractNumber, string name, decimal budget, ContractType contractType, DateOnly baseYearStartDate, DateOnly baseYearEndDate, bool? requiresClinTracking, ComplianceService service) =>
    Results.Ok(service.CreateContract(contractNumber, name, budget, contractType, baseYearStartDate, baseYearEndDate, requiresClinTracking ?? false)));
app.MapPut("/api/compliance/contracts/{contractId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid contractId, string contractNumber, string name, decimal budget, ContractType contractType, DateOnly baseYearStartDate, DateOnly baseYearEndDate, bool? requiresClinTracking, ComplianceService service) =>
    Results.Ok(service.UpdateContract(contractId, contractNumber, name, budget, contractType, baseYearStartDate, baseYearEndDate, requiresClinTracking ?? false)));
app.MapDelete("/api/compliance/contracts/{contractId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid contractId, ComplianceService service) =>
{
    service.DeleteContract(contractId);
    return Results.Ok();
});
app.MapPost("/api/compliance/contracts/{contractId:guid}/option-years", [Authorize(Policy = "RequireCompliance")] (Guid contractId, DateOnly startDate, DateOnly endDate, ComplianceService service) =>
    Results.Ok(service.AddOptionYear(contractId, startDate, endDate)));
app.MapPut("/api/compliance/option-years/{optionYearId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid optionYearId, DateOnly startDate, DateOnly endDate, ComplianceService service) =>
    Results.Ok(service.UpdateOptionYear(optionYearId, startDate, endDate)));
app.MapDelete("/api/compliance/option-years/{optionYearId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid optionYearId, ComplianceService service) =>
{
    service.DeleteOptionYear(optionYearId);
    return Results.Ok();
});
app.MapPost("/api/compliance/taskorders", [Authorize(Policy = "RequireCompliance")] (Guid contractId, string number, decimal budget, bool? requiresClinTracking, ComplianceService service) =>
    Results.Ok(service.CreateTaskOrder(contractId, number, budget, requiresClinTracking)));
app.MapPut("/api/compliance/taskorders/{taskOrderId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid taskOrderId, string number, decimal budget, bool? requiresClinTracking, ComplianceService service) =>
    Results.Ok(service.UpdateTaskOrder(taskOrderId, number, budget, requiresClinTracking)));
app.MapDelete("/api/compliance/taskorders/{taskOrderId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid taskOrderId, ComplianceService service) =>
{
    service.DeleteTaskOrder(taskOrderId);
    return Results.Ok();
});
app.MapPost("/api/compliance/clins", [Authorize(Policy = "RequireCompliance")] (Guid taskOrderId, string number, ComplianceService service) =>
    Results.Ok(service.CreateClin(taskOrderId, number)));
app.MapPut("/api/compliance/clins/{clinId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid clinId, string number, ComplianceService service) =>
    Results.Ok(service.UpdateClin(clinId, number)));
app.MapDelete("/api/compliance/clins/{clinId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid clinId, ComplianceService service) =>
{
    service.DeleteClin(clinId);
    return Results.Ok();
});
app.MapPost("/api/compliance/wbs", [Authorize(Policy = "RequireCompliance")] (Guid clinId, string code, Guid? parentWbsNodeId, ComplianceService service) =>
    Results.Ok(service.CreateWbs(clinId, code, parentWbsNodeId)));
app.MapPut("/api/compliance/wbs/{wbsId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid wbsId, string code, Guid? parentWbsNodeId, ComplianceService service) =>
    Results.Ok(service.UpdateWbs(wbsId, code, parentWbsNodeId)));
app.MapDelete("/api/compliance/wbs/{wbsId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid wbsId, ComplianceService service) =>
{
    service.DeleteWbs(wbsId);
    return Results.Ok();
});
app.MapPost("/api/compliance/chargecodes", [Authorize(Policy = "RequireCompliance")] (Guid wbsId, string code, CostType costType, ComplianceService service) =>
    Results.Ok(service.CreateChargeCode(wbsId, code, costType)));
app.MapPut("/api/compliance/chargecodes/{chargeCodeId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid chargeCodeId, string code, CostType costType, ComplianceService service) =>
    Results.Ok(service.UpdateChargeCode(chargeCodeId, code, costType)));
app.MapDelete("/api/compliance/chargecodes/{chargeCodeId:guid}", [Authorize(Policy = "RequireCompliance")] (Guid chargeCodeId, ComplianceService service) =>
{
    service.DeleteChargeCode(chargeCodeId);
    return Results.Ok();
});
app.MapPost("/api/compliance/contracts/pricing", [Authorize(Policy = "RequireCompliance")] (
    Guid contractId,
    string laborCategory,
    LaborSite site,
    decimal baseHourlyRate,
    decimal escalationPercent,
    decimal feePercent,
    DateOnly effectiveStart,
    DateOnly effectiveEnd,
    ComplianceService service) =>
    Results.Ok(service.AddContractPricing(contractId, laborCategory, site, baseHourlyRate, escalationPercent, feePercent, effectiveStart, effectiveEnd)));
app.MapPost("/api/compliance/chargecodes/lifecycle", [Authorize(Policy = "RequireCompliance")] (Guid chargeCodeId, bool isActive, string reason, ComplianceService service) =>
{
    service.SetChargeCodeActive(chargeCodeId, isActive, reason);
    return Results.Ok();
});
app.MapPost("/api/compliance/supervisor", [Authorize(Policy = "RequireCompliance")] (Guid employeeUserId, Guid supervisorUserId, ComplianceService service) =>
{
    service.SetSupervisor(employeeUserId, supervisorUserId);
    return Results.Ok();
});
app.MapPost("/api/compliance/accounting-periods", [Authorize(Policy = "RequireCompliance")] (DateOnly startDate, DateOnly endDate, ComplianceService service) =>
    Results.Ok(service.CreateAccountingPeriod(startDate, endDate)));
app.MapPost("/api/compliance/accounting-periods/status", [Authorize(Policy = "RequireCompliance")] (Guid periodId, AccountingPeriodStatus status, string reason, ComplianceService service) =>
{
    service.SetAccountingPeriodStatus(periodId, status, reason);
    return Results.Ok();
});
app.MapPost("/api/compliance/allowability-rules", [Authorize(Policy = "RequireCompliance")] (CostType costType, string ruleName, string description, bool requiresComment, ComplianceService service) =>
    Results.Ok(service.UpsertAllowabilityRule(costType, ruleName, description, requiresComment)));
app.MapPost("/api/compliance/assignments", [Authorize(Policy = "RequireCompliance")] (Guid userId, Guid chargeCodeId, DateOnly startDate, DateOnly endDate, bool supervisorOverrideAllowed, ComplianceService service) =>
    Results.Ok(service.AssignUserToChargeCode(userId, chargeCodeId, startDate, endDate, supervisorOverrideAllowed)));
app.MapPost("/api/compliance/out-of-window-approvals", [Authorize(Policy = "RequireSupervisor")] (Guid userId, Guid chargeCodeId, DateOnly workDate, string reason, ComplianceService service) =>
    Results.Ok(service.ApproveOutOfWindowCharge(userId, chargeCodeId, workDate, reason)));
app.MapPost("/api/compliance/overtime-approvals", [Authorize(Policy = "RequireSupervisor")] (Guid userId, DateOnly workDate, int overtimeMinutes, string reason, ComplianceService service) =>
    Results.Ok(service.ApproveOvertimeAllowance(userId, workDate, overtimeMinutes, reason)));
app.MapGet("/api/compliance/forensics", [Authorize(Policy = "RequireCompliance")] (string? entityType, ComplianceService service) =>
    Results.Ok(service.ForensicAuditReport(entityType)));
app.MapPost("/api/compliance/contracts/create-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var contractNumber = form["contractNumber"].ToString();
    var name = form["name"].ToString();
    var baseYearStartDate = DateOnly.TryParse(form["baseYearStartDate"], out var parsedBaseStart)
        ? parsedBaseStart
        : DateOnly.FromDateTime(DateTime.UtcNow.Date);
    var baseYearEndDate = DateOnly.TryParse(form["baseYearEndDate"], out var parsedBaseEnd)
        ? parsedBaseEnd
        : baseYearStartDate.AddYears(1).AddDays(-1);
    _ = decimal.TryParse(form["budget"], out var budget);
    _ = Enum.TryParse<ContractType>(form["contractType"], out var contractType);
    var requiresClinTracking = string.Equals(form["requiresClinTracking"], "true", StringComparison.OrdinalIgnoreCase)
        || string.Equals(form["requiresClinTracking"], "on", StringComparison.OrdinalIgnoreCase)
        || string.Equals(form["requiresClinTracking"], "1", StringComparison.OrdinalIgnoreCase);
    service.CreateContract(contractNumber, name, budget, contractType == 0 ? ContractType.FixedValue : contractType, baseYearStartDate, baseYearEndDate, requiresClinTracking);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/contracts/pricing-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["contractId"], out var contractId) ||
        !DateOnly.TryParse(form["effectiveStart"], out var effectiveStart) ||
        !DateOnly.TryParse(form["effectiveEnd"], out var effectiveEnd))
    {
        return Results.Redirect($"/compliance/contracts?error=invalid_pricing&refresh={DateTime.UtcNow.Ticks}");
    }

    _ = decimal.TryParse(form["baseHourlyRate"], out var baseHourlyRate);
    _ = decimal.TryParse(form["escalationPercent"], out var escalationPercent);
    _ = decimal.TryParse(form["feePercent"], out var feePercent);
    _ = Enum.TryParse<LaborSite>(form["site"], out var site);

    service.AddContractPricing(
        contractId,
        form["laborCategory"].ToString(),
        site == 0 ? LaborSite.GovernmentSite : site,
        baseHourlyRate,
        escalationPercent,
        feePercent,
        effectiveStart,
        effectiveEnd);

    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/taskorders/create-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["contractId"], out var contractId))
    {
        return Results.Redirect($"/compliance/contracts?error=invalid_taskorder&refresh={DateTime.UtcNow.Ticks}");
    }

    _ = decimal.TryParse(form["budget"], out var budget);
    var requiresClinTracking = string.Equals(form["requiresClinTracking"], "true", StringComparison.OrdinalIgnoreCase)
        || string.Equals(form["requiresClinTracking"], "on", StringComparison.OrdinalIgnoreCase)
        || string.Equals(form["requiresClinTracking"], "1", StringComparison.OrdinalIgnoreCase);
    service.CreateTaskOrder(contractId, form["number"].ToString(), budget, requiresClinTracking);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/clins/create-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["taskOrderId"], out var taskOrderId))
    {
        return Results.Redirect($"/compliance/contracts?error=invalid_clin&refresh={DateTime.UtcNow.Ticks}");
    }

    service.CreateClin(taskOrderId, form["number"].ToString());
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/wbs/create-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["clinId"], out var clinId))
    {
        return Results.Redirect($"/compliance/contracts?error=invalid_wbs&refresh={DateTime.UtcNow.Ticks}");
    }

    Guid? parentWbsNodeId = Guid.TryParse(form["parentWbsNodeId"], out var parent) ? parent : null;
    service.CreateWbs(clinId, form["code"].ToString(), parentWbsNodeId);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/chargecodes/create-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["wbsId"], out var wbsId))
    {
        return Results.Redirect($"/compliance/contracts?error=invalid_chargecode&refresh={DateTime.UtcNow.Ticks}");
    }

    _ = Enum.TryParse<CostType>(form["costType"], out var costType);
    service.CreateChargeCode(wbsId, form["code"].ToString(), costType == 0 ? CostType.Direct : costType);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/contracts/{contractId:guid}/update-form", [Authorize(Policy = "RequireCompliance")] async (Guid contractId, HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var baseYearStartDate = DateOnly.TryParse(form["baseYearStartDate"], out var parsedBaseStart)
        ? parsedBaseStart
        : DateOnly.FromDateTime(DateTime.UtcNow.Date);
    var baseYearEndDate = DateOnly.TryParse(form["baseYearEndDate"], out var parsedBaseEnd)
        ? parsedBaseEnd
        : baseYearStartDate.AddYears(1).AddDays(-1);
    _ = decimal.TryParse(form["budget"], out var budget);
    _ = Enum.TryParse<ContractType>(form["contractType"], out var contractType);
    var requiresClinTracking = string.Equals(form["requiresClinTracking"], "true", StringComparison.OrdinalIgnoreCase)
        || string.Equals(form["requiresClinTracking"], "on", StringComparison.OrdinalIgnoreCase)
        || string.Equals(form["requiresClinTracking"], "1", StringComparison.OrdinalIgnoreCase);
    service.UpdateContract(contractId, form["contractNumber"].ToString(), form["name"].ToString(), budget, contractType == 0 ? ContractType.FixedValue : contractType, baseYearStartDate, baseYearEndDate, requiresClinTracking);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/contracts/{contractId:guid}/option-years/create-form", [Authorize(Policy = "RequireCompliance")] async (Guid contractId, HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["startDate"], out var startDate) ||
        !DateOnly.TryParse(form["endDate"], out var endDate))
    {
        return Results.Redirect($"/compliance/contracts?error=invalid_option_year&refresh={DateTime.UtcNow.Ticks}");
    }

    service.AddOptionYear(contractId, startDate, endDate);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/option-years/{optionYearId:guid}/update-form", [Authorize(Policy = "RequireCompliance")] async (Guid optionYearId, HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["startDate"], out var startDate) ||
        !DateOnly.TryParse(form["endDate"], out var endDate))
    {
        return Results.Redirect($"/compliance/contracts?error=invalid_option_year&refresh={DateTime.UtcNow.Ticks}");
    }

    service.UpdateOptionYear(optionYearId, startDate, endDate);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/option-years/{optionYearId:guid}/delete-form", [Authorize(Policy = "RequireCompliance")] (Guid optionYearId, ComplianceService service) =>
{
    service.DeleteOptionYear(optionYearId);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/contracts/{contractId:guid}/delete-form", [Authorize(Policy = "RequireCompliance")] (Guid contractId, ComplianceService service) =>
{
    service.DeleteContract(contractId);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/taskorders/{taskOrderId:guid}/delete-form", [Authorize(Policy = "RequireCompliance")] (Guid taskOrderId, ComplianceService service) =>
{
    service.DeleteTaskOrder(taskOrderId);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/clins/{clinId:guid}/delete-form", [Authorize(Policy = "RequireCompliance")] (Guid clinId, ComplianceService service) =>
{
    service.DeleteClin(clinId);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/wbs/{wbsId:guid}/delete-form", [Authorize(Policy = "RequireCompliance")] (Guid wbsId, ComplianceService service) =>
{
    service.DeleteWbs(wbsId);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/chargecodes/{chargeCodeId:guid}/delete-form", [Authorize(Policy = "RequireCompliance")] (Guid chargeCodeId, ComplianceService service) =>
{
    service.DeleteChargeCode(chargeCodeId);
    return Results.Redirect($"/compliance/contracts?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/chargecodes/{chargeCodeId:guid}/lifecycle-form", [Authorize(Policy = "RequireCompliance")] async (Guid chargeCodeId, HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    _ = bool.TryParse(form["isActive"], out var isActive);
    var reason = form["reason"].ToString();
    service.SetChargeCodeActive(chargeCodeId, isActive, string.IsNullOrWhiteSpace(reason) ? "Lifecycle update" : reason);
    return Results.Redirect("/compliance/contracts");
});
app.MapPost("/api/compliance/supervisor/set-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["employeeUserId"], out var employeeUserId) || !Guid.TryParse(form["supervisorUserId"], out var supervisorUserId))
    {
        return Results.Redirect($"/compliance/assignments?error=invalid_supervisor&refresh={DateTime.UtcNow.Ticks}");
    }

    service.SetSupervisor(employeeUserId, supervisorUserId);
    return Results.Redirect($"/compliance/assignments?refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/assignments/create-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["userId"], out var userId) ||
        !Guid.TryParse(form["chargeCodeId"], out var chargeCodeId) ||
        !DateOnly.TryParse(form["startDate"], out var startDate) ||
        !DateOnly.TryParse(form["endDate"], out var endDate))
    {
        return Results.Redirect($"/compliance/assignments?error=invalid_assignment&refresh={DateTime.UtcNow.Ticks}");
    }

    var supervisorOverrideAllowed = bool.TryParse(form["supervisorOverrideAllowed"], out var parsed) && parsed;
    service.AssignUserToChargeCode(userId, chargeCodeId, startDate, endDate, supervisorOverrideAllowed);
    return Results.Redirect($"/compliance/assignments?saved=1&refresh={DateTime.UtcNow.Ticks}");
});
app.MapPost("/api/compliance/accounting-periods/create-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["startDate"], out var startDate) || !DateOnly.TryParse(form["endDate"], out var endDate))
    {
        return Results.Redirect("/compliance/periods?error=invalid_period");
    }

    service.CreateAccountingPeriod(startDate, endDate);
    return Results.Redirect("/compliance/periods");
});
app.MapPost("/api/compliance/accounting-periods/{periodId:guid}/status-form", [Authorize(Policy = "RequireCompliance")] async (Guid periodId, HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    _ = Enum.TryParse<AccountingPeriodStatus>(form["status"], out var status);
    var reason = form["reason"].ToString();
    service.SetAccountingPeriodStatus(periodId, status == 0 ? AccountingPeriodStatus.Closed : status, string.IsNullOrWhiteSpace(reason) ? "Status update" : reason);
    return Results.Redirect("/compliance/periods");
});
app.MapPost("/api/compliance/allowability-rules/upsert-form", [Authorize(Policy = "RequireCompliance")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    _ = Enum.TryParse<CostType>(form["costType"], out var costType);
    _ = bool.TryParse(form["requiresComment"], out var requiresComment);
    service.UpsertAllowabilityRule(
        costType == 0 ? CostType.Direct : costType,
        form["ruleName"].ToString(),
        form["description"].ToString(),
        requiresComment);
    return Results.Redirect("/compliance/periods");
});

app.MapPost("/api/timesheets/create", [Authorize(Policy = "RequireTimeReporter")] (CreateTimesheetRequest request, TimesheetService service) =>
    Results.Ok(service.CreateTimesheetDraft(request)));
app.MapPost("/api/timesheets/{timesheetId:guid}/lines", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, AddTimesheetLineRequest request, TimesheetService service) =>
    Results.Ok(service.AddLine(timesheetId, request)));
app.MapPut("/api/timesheets/{timesheetId:guid}/lines/{lineId:guid}", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, Guid lineId, UpdateTimesheetLineRequest request, TimesheetService service) =>
    Results.Ok(service.UpdateLine(timesheetId, lineId, request)));
app.MapPost("/api/timesheets/{timesheetId:guid}/expenses", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, AddTimesheetExpenseRequest request, TimesheetService service) =>
    Results.Ok(service.AddExpense(timesheetId, request)));
app.MapPut("/api/timesheets/{timesheetId:guid}/expenses/{expenseId:guid}", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, Guid expenseId, UpdateTimesheetExpenseRequest request, TimesheetService service) =>
    Results.Ok(service.UpdateExpense(timesheetId, expenseId, request)));
app.MapPost("/api/timesheets/{timesheetId:guid}/work-notes", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, AddWorkNoteRequest request, TimesheetService service) =>
    Results.Ok(service.AddWorkNote(timesheetId, request)));
app.MapPost("/api/timesheets/{timesheetId:guid}/weekly-status", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, UpsertWeeklyStatusReportRequest request, TimesheetService service) =>
    Results.Ok(service.UpsertWeeklyStatusReport(timesheetId, request)));
app.MapPost("/api/timesheets/submit", [Authorize(Policy = "RequireTimeReporter")] (SubmitTimesheetRequest request, TimesheetService service) =>
{
    service.Submit(request);
    return Results.Ok();
});
app.MapPost("/api/timesheets/approve", [Authorize(Policy = "RequireSupervisor")] (ApproveTimesheetRequest request, TimesheetService service) =>
{
    service.Approve(request);
    return Results.Ok();
});
app.MapPost("/api/timesheets/corrections/request", [Authorize] (RequestCorrectionRequest request, TimesheetService service) =>
    Results.Ok(service.RequestCorrection(request)));
app.MapPost("/api/timesheets/corrections/apply", [Authorize] (ApplyCorrectionRequest request, TimesheetService service) =>
    Results.Ok(service.ApplyCorrection(request)));
app.MapPost("/api/timereporter/corrections/request-form", [Authorize] async (HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["timesheetId"], out var timesheetId))
    {
        return Results.Redirect("/timereporter/corrections?error=invalid_timesheet");
    }

    var reason = form["reasonForChange"].ToString();
    service.RequestCorrection(new RequestCorrectionRequest(timesheetId, reason));
    return Results.Redirect("/timereporter/corrections");
});
app.MapPost("/api/timereporter/corrections/apply-form", [Authorize] async (HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["timesheetId"], out var timesheetId) ||
        !Guid.TryParse(form["correctionRequestId"], out var correctionRequestId) ||
        !Guid.TryParse(form["chargeCodeId"], out var chargeCodeId) ||
        !DateOnly.TryParse(form["workDate"], out var workDate) ||
        !int.TryParse(form["minutes"], out var minutes))
    {
        return Results.Redirect("/timereporter/corrections?error=invalid_apply");
    }

    var reason = form["reasonForChange"].ToString();
    var comment = form["comment"].ToString();
    var lines = new List<AddTimesheetLineRequest>
    {
        new(workDate, chargeCodeId, minutes, CostType.Direct, comment)
    };
    service.ApplyCorrection(new ApplyCorrectionRequest(timesheetId, correctionRequestId, lines, reason));
    return Results.Redirect("/timereporter/status");
});

app.MapPost("/api/admin/users/{userId:guid}/toggle-mfa-form", [Authorize(Policy = "RequireAdmin")] async (
    Guid userId,
    HttpContext httpContext,
    InMemoryDataStore store,
    UserManager<GovConIdentityUser> userManager,
    IAuditService audit) =>
{
    var user = store.Users.SingleOrDefault(x => x.Id == userId) ?? throw new InvalidOperationException("User not found.");
    var identity = await userManager.FindByIdAsync(userId.ToString()) ?? throw new InvalidOperationException("Identity user not found.");

    var before = user.MfaEnabled;
    user.MfaEnabled = !user.MfaEnabled;
    store.SaveChanges();
    await userManager.SetTwoFactorEnabledAsync(identity, user.MfaEnabled);
    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "AppUser",
        EntityId = user.Id,
        EventType = EventType.MfaEnrollment,
        ActorUserId = Guid.Parse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)!),
        ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = $"MFA toggled from {before} to {user.MfaEnabled}",
        BeforeJson = JsonSerializer.Serialize(new { mfaEnabled = before }),
        AfterJson = JsonSerializer.Serialize(new { mfaEnabled = user.MfaEnabled }),
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    return Results.Redirect("/admin/users");
});
app.MapPost("/api/admin/users/{userId:guid}/toggle-passkey-form", [Authorize(Policy = "RequireAdmin")] async (
    Guid userId,
    HttpContext httpContext,
    InMemoryDataStore store,
    UserManager<GovConIdentityUser> userManager,
    IAuditService audit) =>
{
    var user = store.Users.SingleOrDefault(x => x.Id == userId) ?? throw new InvalidOperationException("User not found.");
    var identity = await userManager.FindByIdAsync(userId.ToString()) ?? throw new InvalidOperationException("Identity user not found.");

    var before = user.PasskeyRequired;
    user.PasskeyRequired = !user.PasskeyRequired;
    store.SaveChanges();
    identity.PasskeyRequired = user.PasskeyRequired;
    await userManager.UpdateAsync(identity);

    var claims = await userManager.GetClaimsAsync(identity);
    foreach (var claim in claims.Where(x => x.Type == "passkey_required").ToList())
    {
        await userManager.RemoveClaimAsync(identity, claim);
    }

    await userManager.AddClaimAsync(identity, new Claim("passkey_required", user.PasskeyRequired.ToString().ToLowerInvariant()));
    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "AppUser",
        EntityId = user.Id,
        EventType = EventType.PasskeyEnrollment,
        ActorUserId = Guid.Parse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)!),
        ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = $"PasskeyRequired toggled from {before} to {user.PasskeyRequired}",
        BeforeJson = JsonSerializer.Serialize(new { passkeyRequired = before }),
        AfterJson = JsonSerializer.Serialize(new { passkeyRequired = user.PasskeyRequired }),
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    return Results.Redirect("/admin/users");
});
app.MapPost("/api/admin/users/{userId:guid}/toggle-disabled-form", [Authorize(Policy = "RequireAdmin")] async (
    Guid userId,
    HttpContext httpContext,
    InMemoryDataStore store,
    UserManager<GovConIdentityUser> userManager,
    IAuditService audit) =>
{
    var user = store.Users.SingleOrDefault(x => x.Id == userId) ?? throw new InvalidOperationException("User not found.");
    var identity = await userManager.FindByIdAsync(userId.ToString()) ?? throw new InvalidOperationException("Identity user not found.");

    var before = user.IsDisabled;
    user.IsDisabled = !user.IsDisabled;
    store.SaveChanges();
    if (user.IsDisabled)
    {
        await userManager.SetLockoutEndDateAsync(identity, DateTimeOffset.MaxValue);
    }
    else
    {
        await userManager.SetLockoutEndDateAsync(identity, null);
        await userManager.ResetAccessFailedCountAsync(identity);
    }

    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "AppUser",
        EntityId = user.Id,
        EventType = EventType.DisableUser,
        ActorUserId = Guid.Parse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)!),
        ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = $"Disabled toggled from {before} to {user.IsDisabled}",
        BeforeJson = JsonSerializer.Serialize(new { disabled = before }),
        AfterJson = JsonSerializer.Serialize(new { disabled = user.IsDisabled }),
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    return Results.Redirect("/admin/users");
});
app.MapPost("/api/admin/users/{userId:guid}/employee-id-form", [Authorize(Policy = "RequireAdmin")] async (
    Guid userId,
    HttpContext httpContext,
    InMemoryDataStore store,
    IAuditService audit) =>
{
    var user = store.Users.SingleOrDefault(x => x.Id == userId)
        ?? throw new InvalidOperationException("User not found.");
    var form = await httpContext.Request.ReadFormAsync();
    var employeeExternalId = form["employeeExternalId"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(employeeExternalId))
    {
        return Results.Redirect("/admin/users?error=invalid_employee_id");
    }

    var before = user.EmployeeExternalId;
    user.EmployeeExternalId = employeeExternalId;
    store.SaveChanges();

    audit.Record(new AuditEvent
    {
        TenantId = user.TenantId,
        EntityType = "AppUser",
        EntityId = user.Id,
        EventType = EventType.UpdateDraft,
        ActorUserId = Guid.TryParse(httpContext.User.FindFirstValue("domain_user_id"), out var actorId) ? actorId : Guid.Empty,
        ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
        OccurredAtUtc = DateTime.UtcNow,
        ReasonForChange = $"EmployeeExternalId changed from {before} to {employeeExternalId}",
        BeforeJson = JsonSerializer.Serialize(new { employeeExternalId = before }),
        AfterJson = JsonSerializer.Serialize(new { employeeExternalId }),
        CorrelationId = Guid.NewGuid().ToString("N")
    });

    return Results.Redirect("/admin/users?saved=1");
});
app.MapPost("/api/admin/users/{userId:guid}/roles-form", [Authorize(Policy = "RequireAdmin")] async (
    Guid userId,
    HttpContext httpContext,
    InMemoryDataStore store,
    UserManager<GovConIdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    IAuditService audit) =>
{
    var user = store.Users.SingleOrDefault(x => x.Id == userId)
        ?? throw new InvalidOperationException("User not found.");
    var identity = await userManager.FindByIdAsync(userId.ToString())
        ?? throw new InvalidOperationException("Identity user not found.");
    var form = await httpContext.Request.ReadFormAsync();
    var role = form["role"].ToString().Trim();
    var action = form["action"].ToString().Trim().ToLowerInvariant();
    var allowedRoles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Admin", "Compliance", "TimeReporter", "Supervisor", "Accountant", "Manager"
    };
    if (!allowedRoles.Contains(role))
    {
        return Results.Redirect("/admin/users?error=invalid_role");
    }

    var actorId = Guid.TryParse(httpContext.User.FindFirstValue("domain_user_id"), out var parsedActorId) ? parsedActorId : Guid.Empty;
    if (string.Equals(action, "remove", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(role, "Admin", StringComparison.OrdinalIgnoreCase) &&
        actorId == userId)
    {
        return Results.Redirect("/admin/users?error=cannot_remove_own_admin");
    }

    var currentRoles = await userManager.GetRolesAsync(identity);
    var hasRole = currentRoles.Contains(role, StringComparer.OrdinalIgnoreCase);
    if (string.Equals(action, "add", StringComparison.OrdinalIgnoreCase))
    {
        if (hasRole)
        {
            return Results.Redirect("/admin/users?saved=1");
        }

        if (!await roleManager.RoleExistsAsync(role))
        {
            var createRole = await roleManager.CreateAsync(new IdentityRole(role));
            if (!createRole.Succeeded)
            {
                return Results.Redirect("/admin/users?error=role_create_failed");
            }
        }

        var addResult = await userManager.AddToRoleAsync(identity, role);
        if (!addResult.Succeeded)
        {
            return Results.Redirect("/admin/users?error=role_add_failed");
        }

        if (!user.Roles.Contains(role, StringComparer.OrdinalIgnoreCase))
        {
            user.Roles.Add(role);
        }

        store.SaveChanges();
        audit.Record(new AuditEvent
        {
            TenantId = user.TenantId,
            EntityType = "UserRole",
            EntityId = user.Id,
            EventType = EventType.RoleChange,
            ActorUserId = actorId,
            ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
            OccurredAtUtc = DateTime.UtcNow,
            ReasonForChange = $"Role added: {role}",
            AfterJson = JsonSerializer.Serialize(new { role, action = "add" }),
            CorrelationId = Guid.NewGuid().ToString("N")
        });
    }
    else if (string.Equals(action, "remove", StringComparison.OrdinalIgnoreCase))
    {
        if (!hasRole)
        {
            return Results.Redirect("/admin/users?saved=1");
        }

        var removeResult = await userManager.RemoveFromRoleAsync(identity, role);
        if (!removeResult.Succeeded)
        {
            return Results.Redirect("/admin/users?error=role_remove_failed");
        }

        user.Roles.RemoveAll(x => string.Equals(x, role, StringComparison.OrdinalIgnoreCase));
        store.SaveChanges();
        audit.Record(new AuditEvent
        {
            TenantId = user.TenantId,
            EntityType = "UserRole",
            EntityId = user.Id,
            EventType = EventType.RoleChange,
            ActorUserId = actorId,
            ActorRoles = string.Join(",", httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value)),
            OccurredAtUtc = DateTime.UtcNow,
            ReasonForChange = $"Role removed: {role}",
            AfterJson = JsonSerializer.Serialize(new { role, action = "remove" }),
            CorrelationId = Guid.NewGuid().ToString("N")
        });
    }
    else
    {
        return Results.Redirect("/admin/users?error=invalid_action");
    }

    return Results.Redirect("/admin/users?saved=1");
});

app.MapPost("/api/timereporter/drafts/create-form", [Authorize(Policy = "RequireTimeReporter")] async (HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) || !DateOnly.TryParse(form["periodEnd"], out var periodEnd))
    {
        return Results.Redirect("/timereporter/daily?error=invalid_period");
    }

    try
    {
        var draft = service.CreateTimesheetDraft(new CreateTimesheetRequest(periodStart, periodEnd));
        return Results.Redirect($"/timereporter/daily?timesheetId={draft.Id}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/timereporter/daily?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/add-line-form", [Authorize(Policy = "RequireTimeReporter")] async (Guid timesheetId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    _ = Enum.TryParse<TimesheetEntryType>(form["entryType"], out var entryType);
    entryType = entryType == 0 ? TimesheetEntryType.Work : entryType;
    if (!DateOnly.TryParse(form["workDate"], out var workDate) ||
        !int.TryParse(form["minutes"], out var minutes))
    {
        return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&error=invalid_line");
    }

    var chargeCodeId = Guid.Empty;
    if (entryType == TimesheetEntryType.Work && !Guid.TryParse(form["chargeCodeId"], out chargeCodeId))
    {
        return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&error=invalid_line");
    }

    var comment = form["comment"].ToString();
    service.AddLine(timesheetId, new AddTimesheetLineRequest(workDate, chargeCodeId, minutes, CostType.Direct, comment, entryType));
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/lines/{lineId:guid}/edit-form", [Authorize(Policy = "RequireTimeReporter")] async (Guid timesheetId, Guid lineId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    _ = Enum.TryParse<TimesheetEntryType>(form["entryType"], out var entryType);
    entryType = entryType == 0 ? TimesheetEntryType.Work : entryType;
    if (!DateOnly.TryParse(form["workDate"], out var workDate) ||
        !int.TryParse(form["minutes"], out var minutes))
    {
        return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&error=invalid_edit_line");
    }

    var chargeCodeId = Guid.Empty;
    if (entryType == TimesheetEntryType.Work && !Guid.TryParse(form["chargeCodeId"], out chargeCodeId))
    {
        return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&error=invalid_edit_line");
    }

    var comment = form["comment"].ToString();
    service.UpdateLine(timesheetId, lineId, new UpdateTimesheetLineRequest(workDate, chargeCodeId, minutes, CostType.Direct, comment, entryType));
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&updated=1");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/expenses/add-form", [Authorize(Policy = "RequireTimeReporter")] async (Guid timesheetId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["expenseDate"], out var expenseDate) ||
        !Guid.TryParse(form["chargeCodeId"], out var chargeCodeId) ||
        !decimal.TryParse(form["amount"], out var amount))
    {
        return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&error=invalid_expense");
    }

    _ = Enum.TryParse<CostType>(form["costType"], out var costType);
    service.AddExpense(timesheetId, new AddTimesheetExpenseRequest(
        expenseDate,
        chargeCodeId,
        amount,
        costType == 0 ? CostType.Direct : costType,
        form["category"].ToString(),
        form["description"].ToString()));
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&expenseSaved=1");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/expenses/{expenseId:guid}/edit-form", [Authorize(Policy = "RequireTimeReporter")] async (Guid timesheetId, Guid expenseId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["expenseDate"], out var expenseDate) ||
        !Guid.TryParse(form["chargeCodeId"], out var chargeCodeId) ||
        !decimal.TryParse(form["amount"], out var amount))
    {
        return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&error=invalid_edit_expense");
    }

    _ = Enum.TryParse<CostType>(form["costType"], out var costType);
    service.UpdateExpense(timesheetId, expenseId, new UpdateTimesheetExpenseRequest(
        expenseDate,
        chargeCodeId,
        amount,
        costType == 0 ? CostType.Direct : costType,
        form["category"].ToString(),
        form["description"].ToString()));
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&expenseUpdated=1");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/expenses/{expenseId:guid}/delete-form", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, Guid expenseId, TimesheetService service) =>
{
    service.DeleteExpense(timesheetId, expenseId);
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&expenseDeleted=1");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/expenses/{expenseId:guid}/void-form", [Authorize(Policy = "RequireTimeReporter")] async (Guid timesheetId, Guid expenseId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var reason = form["reason"].ToString();
    service.VoidExpense(timesheetId, expenseId, string.IsNullOrWhiteSpace(reason) ? "Voided by time reporter." : reason);
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&expenseVoided=1");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/work-notes/add-form", [Authorize(Policy = "RequireTimeReporter")] async (Guid timesheetId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var note = form["note"].ToString();
    service.AddWorkNote(timesheetId, new AddWorkNoteRequest(note));
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&noteSaved=1");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/weekly-status/save-form", [Authorize(Policy = "RequireTimeReporter")] async (Guid timesheetId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var narrative = form["narrative"].ToString();
    service.UpsertWeeklyStatusReport(timesheetId, new UpsertWeeklyStatusReportRequest(narrative));
    return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&weeklyStatusSaved=1");
});
app.MapPost("/api/timereporter/drafts/{timesheetId:guid}/submit-form", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, TimesheetService service) =>
{
    try
    {
        service.Submit(new SubmitTimesheetRequest(timesheetId, "I attest this entry is accurate."));
        return Results.Redirect("/timereporter/status");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/timereporter/daily?timesheetId={timesheetId}&error={Uri.EscapeDataString(ex.Message)}");
    }
});

app.MapPost("/api/supervisor/timesheets/{timesheetId:guid}/approve-form", [Authorize(Policy = "RequireSupervisor")] (Guid timesheetId, TimesheetService service) =>
{
    service.Approve(new ApproveTimesheetRequest(timesheetId));
    return Results.Redirect("/supervisor/approvals");
});
app.MapPost("/api/supervisor/timesheets/{timesheetId:guid}/expenses/{expenseId:guid}/approve-form", [Authorize(Policy = "RequireSupervisor")] (Guid timesheetId, Guid expenseId, TimesheetService service) =>
{
    service.ApproveExpense(timesheetId, expenseId);
    return Results.Redirect("/supervisor/approvals");
});
app.MapPost("/api/supervisor/timesheets/{timesheetId:guid}/expenses/{expenseId:guid}/reject-form", [Authorize(Policy = "RequireSupervisor")] async (Guid timesheetId, Guid expenseId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var reason = form["reason"].ToString();
    service.RejectExpense(timesheetId, expenseId, string.IsNullOrWhiteSpace(reason) ? "Rejected by supervisor." : reason);
    return Results.Redirect("/supervisor/approvals");
});
app.MapPost("/api/supervisor/overrides/approve-form", [Authorize(Policy = "RequireSupervisor")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["userId"], out var userId) ||
        !Guid.TryParse(form["chargeCodeId"], out var chargeCodeId) ||
        !DateOnly.TryParse(form["workDate"], out var workDate))
    {
        return Results.Redirect("/supervisor/overrides?error=invalid_input");
    }

    var reason = form["reason"].ToString();
    service.ApproveOutOfWindowCharge(userId, chargeCodeId, workDate, reason);
    return Results.Redirect("/supervisor/overrides?saved=1");
});
app.MapPost("/api/supervisor/overtime/approve-form", [Authorize(Policy = "RequireSupervisor")] async (HttpContext httpContext, ComplianceService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["userId"], out var userId) ||
        !DateOnly.TryParse(form["workDate"], out var workDate) ||
        !int.TryParse(form["overtimeMinutes"], out var overtimeMinutes))
    {
        return Results.Redirect("/supervisor/overrides?error=invalid_overtime_input");
    }

    var reason = form["reason"].ToString();
    service.ApproveOvertimeAllowance(userId, workDate, overtimeMinutes, reason);
    return Results.Redirect("/supervisor/overrides?overtimeSaved=1");
});

app.MapGet("/api/reports/labor", [Authorize(Policy = "RequireAccountant")] (string? format, ReportingService reporting) =>
{
    var rows = reporting.LaborDistribution();
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/project", [Authorize(Policy = "RequireAccountant")] (string? format, ReportingService reporting) =>
{
    var rows = reporting.ProjectSummary();
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/compliance", [Authorize(Policy = "RequireAccountant")] (string? format, ReportingService reporting) =>
{
    var rows = reporting.TimesheetCompliance();
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/audit", [Authorize(Policy = "RequireAccountant")] (string? format, string? entityType, EventType? eventType, ReportingService reporting) =>
{
    var rows = reporting.SearchAudit(entityType, eventType);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        var csvRows = rows.Select(x => new { x.OccurredAtUtc, x.EntityType, x.EventType, x.ActorUserId, x.ReasonForChange });
        return Results.Text(ExportService.ToCsv(csvRows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/journal", [Authorize(Policy = "RequireAccountant")] (string? format, DateOnly? fromDate, DateOnly? toDate, ReportingService reporting) =>
{
    var rows = reporting.GeneralJournal(fromDate, toDate);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/payroll-reconciliation", [Authorize(Policy = "RequireAccountant")] (string? format, DateOnly? fromDate, DateOnly? toDate, PayrollService payroll) =>
{
    var rows = payroll.Reconciliation(fromDate, toDate);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/trial-balance", [Authorize(Policy = "RequireManagerOrAccountant")] (string? format, DateOnly periodStart, DateOnly periodEnd, CloseService close) =>
{
    var rows = close.TrialBalance(periodStart, periodEnd);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/subledger-gl-reconciliation", [Authorize(Policy = "RequireManagerOrAccountant")] (string? format, DateOnly periodStart, DateOnly periodEnd, CloseService close) =>
{
    var rows = close.SubledgerToGlReconciliation(periodStart, periodEnd);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/monthly-close-compliance", [Authorize(Policy = "RequireManagerOrAccountant")] (string? format, DateOnly? asOfDate, int? closeGraceDays, MonthlyCloseComplianceService monthlyClose) =>
{
    var rows = monthlyClose.CloseCadenceStatus(asOfDate, closeGraceDays ?? 10);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/internal-audit-compliance", [Authorize(Policy = "RequireComplianceManagerOrAccountant")] (string? format, DateOnly? asOfDate, InternalAuditService internalAudit) =>
{
    var rows = internalAudit.ComplianceReport(asOfDate);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/internal-audit-cycles", [Authorize(Policy = "RequireComplianceManagerOrAccountant")] (string? format, DateOnly? periodStart, DateOnly? periodEnd, InternalAuditService internalAudit) =>
{
    var rows = internalAudit.Cycles(periodStart, periodEnd);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/internal-audit-attestations", [Authorize(Policy = "RequireComplianceManagerOrAccountant")] (string? format, Guid? internalAuditCycleId, InternalAuditService internalAudit) =>
{
    var rows = internalAudit.Attestations(internalAuditCycleId);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/indirect-rates", [Authorize(Policy = "RequireManagerOrAccountant")] (string? format, DateOnly? fromDate, DateOnly? toDate, IndirectRateService indirect) =>
{
    var rows = indirect.RateSupport(fromDate, toDate);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/indirect-burdens", [Authorize(Policy = "RequireManagerOrAccountant")] (string? format, DateOnly? fromDate, DateOnly? toDate, IndirectRateService indirect) =>
{
    var rows = indirect.BurdenSummary(fromDate, toDate);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/billing-reconciliation", [Authorize(Policy = "RequireManagerOrAccountant")] (string? format, DateOnly periodStart, DateOnly periodEnd, Guid? contractId, BillingService billing) =>
{
    var rows = billing.BilledToBookedReconciliation(periodStart, periodEnd, contractId);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});
app.MapGet("/api/reports/clin-summary", [Authorize(Policy = "RequireAccountant")] (string? format, DateOnly periodStart, DateOnly periodEnd, Guid? contractId, ReportingService reporting) =>
{
    var rows = reporting.ClinSummary(periodStart, periodEnd, contractId);
    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Text(ExportService.ToCsv(rows), "text/csv");
    }

    return Results.Json(rows);
});

app.MapPost("/api/accountant/ledger/post-form", [Authorize(Policy = "RequireAccountant")] (AccountingService accounting) =>
{
    var posted = accounting.PostApprovedTimeCardsToLedger();
    return Results.Redirect($"/accountant/reports/journal?posted={posted}");
});
app.MapGet("/api/accountant/billing/runs", [Authorize(Policy = "RequireAccountant")] (BillingService billing) =>
{
    return Results.Json(billing.BillingRuns());
});
app.MapGet("/api/accountant/billing/invoices", [Authorize(Policy = "RequireAccountant")] (ITenantContext tenantContext, InMemoryDataStore store, Guid? billingRunId) =>
{
    var query = store.Invoices.Where(x => x.TenantId == tenantContext.TenantId);
    if (billingRunId.HasValue)
    {
        query = query.Where(x => x.BillingRunId == billingRunId.Value);
    }

    var contracts = store.Contracts.Where(x => x.TenantId == tenantContext.TenantId).ToDictionary(x => x.Id, x => x.ContractNumber);
    var rows = query.OrderByDescending(x => x.CreatedAtUtc).ToList()
        .Select(x => new
        {
            x.Id,
            x.BillingRunId,
            x.ContractId,
            ContractNumber = contracts.TryGetValue(x.ContractId, out var number) ? number : "(unknown)",
            x.InvoiceNumber,
            x.PeriodStart,
            x.PeriodEnd,
            x.Status,
            x.TotalAmount
        })
        .ToList();
    return Results.Json(rows);
});
app.MapGet("/api/accountant/billing/ceilings", [Authorize(Policy = "RequireAccountant")] (ITenantContext tenantContext, InMemoryDataStore store) =>
{
    var contracts = store.Contracts.Where(x => x.TenantId == tenantContext.TenantId).ToDictionary(x => x.Id, x => x.ContractNumber);
    var rows = store.BillingCeilings
        .Where(x => x.TenantId == tenantContext.TenantId)
        .OrderBy(x => contracts.ContainsKey(x.ContractId) ? contracts[x.ContractId] : string.Empty)
        .ToList()
        .Select(x => new
        {
            x.Id,
            x.ContractId,
            ContractNumber = contracts.TryGetValue(x.ContractId, out var number) ? number : "(unknown)",
            x.FundedAmount,
            x.CeilingAmount,
            x.EffectiveStartDate,
            x.EffectiveEndDate,
            x.IsActive
        })
        .ToList();
    return Results.Json(rows);
});
app.MapPost("/api/accountant/billing/ceiling-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, BillingService billing) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["contractId"], out var contractId) ||
        !decimal.TryParse(form["fundedAmount"], out var fundedAmount) ||
        !decimal.TryParse(form["ceilingAmount"], out var ceilingAmount) ||
        !DateOnly.TryParse(form["effectiveStartDate"], out var effectiveStartDate) ||
        !DateOnly.TryParse(form["effectiveEndDate"], out var effectiveEndDate))
    {
        return Results.Redirect("/accountant/reports/billing?error=invalid_ceiling");
    }

    var isActive = !string.Equals(form["isActive"], "false", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(form["isActive"], "0", StringComparison.OrdinalIgnoreCase);
    try
    {
        billing.UpsertCeiling(new UpsertBillingCeilingRequest(
            contractId,
            fundedAmount,
            ceilingAmount,
            effectiveStartDate,
            effectiveEndDate,
            isActive));
        return Results.Redirect("/accountant/reports/billing?ceilingSaved=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/billing?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/billing/generate-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, BillingService billing) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) ||
        !DateOnly.TryParse(form["periodEnd"], out var periodEnd))
    {
        return Results.Redirect("/accountant/reports/billing?error=invalid_period");
    }

    Guid? contractId = Guid.TryParse(form["contractId"], out var parsedContractId) ? parsedContractId : null;
    try
    {
        var run = billing.GenerateBillingRun(new CreateBillingRunRequest(periodStart, periodEnd, contractId, form["notes"].ToString()));
        return Results.Redirect($"/accountant/reports/billing?generated={run.Id}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/billing?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/manager/billing/approve-form", [Authorize(Policy = "RequireManagerOrAccountant")] async (HttpContext httpContext, BillingService billing) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["billingRunId"], out var billingRunId))
    {
        return Results.Redirect("/accountant/reports/billing?error=invalid_billing_run");
    }

    try
    {
        billing.ApproveBillingRun(new ApproveBillingRunRequest(billingRunId, form["reason"].ToString()));
        return Results.Redirect("/accountant/reports/billing?approved=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/billing?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/billing/post-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, BillingService billing) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["billingRunId"], out var billingRunId))
    {
        return Results.Redirect("/accountant/reports/billing?error=invalid_billing_run");
    }

    try
    {
        billing.PostBillingRun(new PostBillingRunRequest(billingRunId, form["reason"].ToString()));
        return Results.Redirect("/accountant/reports/billing?posted=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/billing?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapGet("/api/accountant/journal/adjusting", [Authorize(Policy = "RequireManagerOrAccountant")] (ITenantContext tenantContext, InMemoryDataStore store) =>
{
    var rows = store.JournalEntries
        .Where(x => x.TenantId == tenantContext.TenantId && x.EntryType == JournalEntryType.Adjusting)
        .OrderByDescending(x => x.EntryDate)
        .ThenByDescending(x => x.Id)
        .Select(x => new
        {
            x.Id,
            x.EntryDate,
            x.Description,
            x.Status,
            x.Reason,
            x.RequestedByUserId,
            x.ApprovedByUserId,
            x.PostedAtUtc,
            x.ReversalOfJournalEntryId,
            x.IsReversal
        })
        .ToList();
    return Results.Json(rows);
});
app.MapPost("/api/accountant/journal/adjusting/create-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, JournalEntryWorkflowService workflow) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["entryDate"], out var entryDate))
    {
        return Results.Redirect("/accountant/reports/adjusting-journal?error=invalid_entry_date");
    }

    var accountIds = form["lineAccountId"];
    var debits = form["lineDebit"];
    var credits = form["lineCredit"];
    var lines = new List<AdjustingJournalLineRequest>();
    var lineCount = Math.Max(accountIds.Count, Math.Max(debits.Count, credits.Count));
    for (var i = 0; i < lineCount; i++)
    {
        if (!Guid.TryParse(accountIds.ElementAtOrDefault(i), out var accountId))
        {
            continue;
        }

        _ = decimal.TryParse(debits.ElementAtOrDefault(i), out var debit);
        _ = decimal.TryParse(credits.ElementAtOrDefault(i), out var credit);
        if (debit == 0m && credit == 0m)
        {
            continue;
        }

        lines.Add(new AdjustingJournalLineRequest(accountId, debit, credit));
    }

    try
    {
        var entry = workflow.CreateAdjustingEntry(new CreateAdjustingJournalEntryRequest(
            entryDate,
            form["description"].ToString(),
            form["reason"].ToString(),
            form["attachmentRefs"].ToString(),
            lines));
        return Results.Redirect($"/accountant/reports/adjusting-journal?created={entry.Id}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/adjusting-journal?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/journal/adjusting/submit-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, JournalEntryWorkflowService workflow) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["journalEntryId"], out var journalEntryId))
    {
        return Results.Redirect("/accountant/reports/adjusting-journal?error=invalid_journal_entry");
    }

    try
    {
        var reason = form["reason"].ToString();
        workflow.SubmitAdjustingEntry(new SubmitAdjustingJournalEntryRequest(journalEntryId, reason));
        return Results.Redirect("/accountant/reports/adjusting-journal?submitted=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/adjusting-journal?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/manager/journal/adjusting/approve-form", [Authorize(Policy = "RequireManagerOrAccountant")] async (HttpContext httpContext, JournalEntryWorkflowService workflow) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["journalEntryId"], out var journalEntryId))
    {
        return Results.Redirect("/accountant/reports/adjusting-journal?error=invalid_journal_entry");
    }

    try
    {
        var reason = form["reason"].ToString();
        var attachmentRefs = form["attachmentRefs"].ToString();
        workflow.ApproveAdjustingEntry(new ApproveAdjustingJournalEntryRequest(
            journalEntryId,
            reason,
            attachmentRefs));
        return Results.Redirect("/accountant/reports/adjusting-journal?approved=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/adjusting-journal?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/journal/adjusting/post-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, JournalEntryWorkflowService workflow) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["journalEntryId"], out var journalEntryId))
    {
        return Results.Redirect("/accountant/reports/adjusting-journal?error=invalid_journal_entry");
    }

    try
    {
        var reason = form["reason"].ToString();
        workflow.PostApprovedEntry(new PostAdjustingJournalEntryRequest(journalEntryId, reason));
        return Results.Redirect("/accountant/reports/adjusting-journal?posted=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/adjusting-journal?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/journal/adjusting/reverse-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, JournalEntryWorkflowService workflow) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["journalEntryId"], out var journalEntryId))
    {
        return Results.Redirect("/accountant/reports/adjusting-journal?error=invalid_journal_entry");
    }

    DateOnly? reversalDate = null;
    if (DateOnly.TryParse(form["reversalDate"], out var parsedDate))
    {
        reversalDate = parsedDate;
    }

    try
    {
        var reason = form["reason"].ToString();
        workflow.ReverseEntry(new ReverseJournalEntryRequest(journalEntryId, reversalDate, reason));
        return Results.Redirect("/accountant/reports/adjusting-journal?reversed=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/adjusting-journal?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/payroll/import", [Authorize(Policy = "RequireAccountant")] (PayrollImportBatchRequest request, PayrollService payroll) =>
{
    var batch = payroll.ImportBatch(request);
    return Results.Ok(new { batch.Id, batch.ExternalBatchId, batch.PeriodStart, batch.PeriodEnd });
});
app.MapPost("/api/accountant/period-close/validate-form", [Authorize(Policy = "RequireManagerOrAccountant")] async (HttpContext httpContext, CloseService close) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) || !DateOnly.TryParse(form["periodEnd"], out var periodEnd))
    {
        return Results.Redirect("/accountant/reports/period-close?error=invalid_period");
    }

    try
    {
        var checks = close.PreCloseValidation(periodStart, periodEnd);
        var failedCount = checks.Count(x => !x.Passed);
        return Results.Redirect($"/accountant/reports/period-close?periodStart={periodStart:yyyy-MM-dd}&periodEnd={periodEnd:yyyy-MM-dd}&validated=1&failed={failedCount}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/period-close?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/manager/period-close/close-form", [Authorize(Policy = "RequireManager")] async (HttpContext httpContext, CloseService close) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["accountingPeriodId"], out var periodId))
    {
        return Results.Redirect("/accountant/reports/period-close?error=invalid_period_id");
    }

    try
    {
        close.ClosePeriod(periodId, form["notes"]);
        return Results.Redirect("/accountant/reports/period-close?closed=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/period-close?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/internal-audit/sync-form", [Authorize(Policy = "RequireComplianceManagerOrAccountant")] async (HttpContext httpContext, InternalAuditService internalAudit) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var asOfDate = DateOnly.TryParse(form["asOfDate"], out var parsedAsOfDate) ? parsedAsOfDate : (DateOnly?)null;
    internalAudit.SyncCycles(asOfDate);
    return Results.Redirect("/accountant/reports/period-close?internalAuditSynced=1");
});
app.MapPost("/api/internal-audit/checklist-form", [Authorize(Policy = "RequireComplianceManagerOrAccountant")] async (HttpContext httpContext, InternalAuditService internalAudit) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["internalAuditCycleId"], out var cycleId))
    {
        return Results.Redirect("/accountant/reports/period-close?error=invalid_internal_audit_cycle");
    }

    var request = new UpsertInternalAuditChecklistRequest(
        cycleId,
        ParseCheckbox(form, "tieOutReviewCompleted"),
        ParseCheckbox(form, "unallowableReviewCompleted"),
        ParseCheckbox(form, "billingReviewCompleted"),
        ParseCheckbox(form, "monthlyCloseReviewCompleted"),
        form["notes"]);

    try
    {
        internalAudit.UpsertChecklist(request);
        return Results.Redirect("/accountant/reports/period-close?internalAuditChecklistSaved=1");
    }
    catch (Exception ex)
    {
        return Results.Redirect($"/accountant/reports/period-close?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/internal-audit/submit-form", [Authorize(Policy = "RequireComplianceManagerOrAccountant")] async (HttpContext httpContext, InternalAuditService internalAudit) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["internalAuditCycleId"], out var cycleId))
    {
        return Results.Redirect("/accountant/reports/period-close?error=invalid_internal_audit_cycle");
    }

    try
    {
        internalAudit.SubmitForAttestation(new SubmitInternalAuditCycleRequest(cycleId, form["summary"].ToString()));
        return Results.Redirect("/accountant/reports/period-close?internalAuditSubmitted=1");
    }
    catch (Exception ex)
    {
        return Results.Redirect($"/accountant/reports/period-close?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/internal-audit/attest-form", [Authorize(Policy = "RequireComplianceManagerOrAccountant")] async (HttpContext httpContext, InternalAuditService internalAudit) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["internalAuditCycleId"], out var cycleId))
    {
        return Results.Redirect("/accountant/reports/period-close?error=invalid_internal_audit_cycle");
    }

    if (!Enum.TryParse<InternalAuditAttestationType>(form["attestationType"], true, out var attestationType))
    {
        return Results.Redirect("/accountant/reports/period-close?error=invalid_attestation_type");
    }

    try
    {
        internalAudit.RecordAttestation(new RecordInternalAuditAttestationRequest(cycleId, attestationType, form["statement"].ToString(), form["notes"].ToString()));
        return Results.Redirect("/accountant/reports/period-close?internalAuditAttested=1");
    }
    catch (Exception ex)
    {
        return Results.Redirect($"/accountant/reports/period-close?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/internal-audit/complete-form", [Authorize(Policy = "RequireManager")] async (HttpContext httpContext, InternalAuditService internalAudit) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["internalAuditCycleId"], out var cycleId))
    {
        return Results.Redirect("/accountant/reports/period-close?error=invalid_internal_audit_cycle");
    }

    try
    {
        internalAudit.CompleteCycle(new CompleteInternalAuditCycleRequest(cycleId, form["notes"].ToString()));
        return Results.Redirect("/accountant/reports/period-close?internalAuditCompleted=1");
    }
    catch (Exception ex)
    {
        return Results.Redirect($"/accountant/reports/period-close?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/indirect/compute-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, IndirectRateService indirect) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) || !DateOnly.TryParse(form["periodEnd"], out var periodEnd))
    {
        return Results.Redirect("/accountant/reports/indirect?error=invalid_period");
    }

    var isFinal = string.Equals(form["isFinal"], "true", StringComparison.OrdinalIgnoreCase);
    try
    {
        var rows = indirect.ComputeRates(new ComputeIndirectRatesRequest(periodStart, periodEnd, isFinal));
        return Results.Redirect($"/accountant/reports/indirect?computed={rows.Count}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/indirect?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/indirect/apply-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, IndirectRateService indirect) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) || !DateOnly.TryParse(form["periodEnd"], out var periodEnd))
    {
        return Results.Redirect("/accountant/reports/indirect?error=invalid_period");
    }

    Guid? poolId = Guid.TryParse(form["indirectPoolId"], out var parsedPoolId) ? parsedPoolId : null;
    Guid? rateCalcId = Guid.TryParse(form["rateCalculationId"], out var parsedRateCalcId) ? parsedRateCalcId : null;
    var postToGeneralLedger = !string.Equals(form["postToGeneralLedger"], "false", StringComparison.OrdinalIgnoreCase);
    try
    {
        var rows = indirect.ApplyBurden(new ApplyIndirectBurdenRequest(periodStart, periodEnd, poolId, rateCalcId, postToGeneralLedger));
        return Results.Redirect($"/accountant/reports/indirect?applied={rows.Count}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/indirect?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/indirect/rerate-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, IndirectRateService indirect) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) ||
        !DateOnly.TryParse(form["periodEnd"], out var periodEnd) ||
        !Guid.TryParse(form["indirectPoolId"], out var poolId) ||
        !decimal.TryParse(form["newRate"], out var newRate))
    {
        return Results.Redirect("/accountant/reports/indirect?error=invalid_rerate");
    }

    var isFinal = string.Equals(form["isFinal"], "true", StringComparison.OrdinalIgnoreCase);
    var postToGeneralLedger = !string.Equals(form["postToGeneralLedger"], "false", StringComparison.OrdinalIgnoreCase);
    try
    {
        var rows = indirect.Rerate(new RerateIndirectBurdenRequest(periodStart, periodEnd, poolId, newRate, isFinal, postToGeneralLedger));
        return Results.Redirect($"/accountant/reports/indirect?rerated={rows.Count}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/indirect?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/indirect/submit-final-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, IndirectRateService indirect) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["rateCalculationId"], out var rateCalculationId))
    {
        return Results.Redirect("/accountant/reports/indirect?error=invalid_rate_calculation");
    }

    try
    {
        indirect.SubmitFinalForManagerReview(rateCalculationId, form["reason"]);
        return Results.Redirect("/accountant/reports/indirect?submitted=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/indirect?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/manager/indirect/approve-form", [Authorize(Policy = "RequireManager")] async (HttpContext httpContext, IndirectRateService indirect) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["rateCalculationId"], out var rateCalculationId))
    {
        return Results.Redirect("/accountant/reports/indirect?error=invalid_rate_calculation");
    }

    var reason = form["reason"].ToString();
    if (string.IsNullOrWhiteSpace(reason))
    {
        reason = "Approved by manager.";
    }

    try
    {
        indirect.ApproveFinalRate(rateCalculationId, reason);
        return Results.Redirect("/accountant/reports/indirect?managerApproved=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/indirect?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/manager/indirect/reject-form", [Authorize(Policy = "RequireManager")] async (HttpContext httpContext, IndirectRateService indirect) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["rateCalculationId"], out var rateCalculationId))
    {
        return Results.Redirect("/accountant/reports/indirect?error=invalid_rate_calculation");
    }

    var reason = form["reason"].ToString();
    if (string.IsNullOrWhiteSpace(reason))
    {
        return Results.Redirect("/accountant/reports/indirect?error=manager_rejection_reason_required");
    }

    try
    {
        indirect.RejectFinalRate(rateCalculationId, reason);
        return Results.Redirect("/accountant/reports/indirect?managerRejected=1");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/indirect?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapGet("/api/accountant/payroll/import-profiles", [Authorize(Policy = "RequireAccountant")] (PayrollService payroll) =>
{
    var rows = payroll.GetImportProfiles(includeInactive: true);
    return Results.Json(rows);
});
app.MapPost("/api/accountant/payroll/import-profiles-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, PayrollService payroll) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    Guid? profileId = null;
    if (Guid.TryParse(form["profileId"], out var parsedProfileId))
    {
        profileId = parsedProfileId;
    }

    var hasHeaderRow = !string.Equals(form["hasHeaderRow"], "false", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(form["hasHeaderRow"], "0", StringComparison.OrdinalIgnoreCase);
    var isActive = !string.Equals(form["isActive"], "false", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(form["isActive"], "0", StringComparison.OrdinalIgnoreCase);
    var requireKnownEmployee = !string.Equals(form["requireKnownEmployeeExternalId"], "false", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(form["requireKnownEmployeeExternalId"], "0", StringComparison.OrdinalIgnoreCase);
    var disallowDuplicates = !string.Equals(form["disallowDuplicateEmployeeExternalIds"], "false", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(form["disallowDuplicateEmployeeExternalIds"], "0", StringComparison.OrdinalIgnoreCase);
    var requirePositiveLabor = !string.Equals(form["requirePositiveLaborAmount"], "false", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(form["requirePositiveLaborAmount"], "0", StringComparison.OrdinalIgnoreCase);

    try
    {
        var profile = payroll.UpsertImportProfile(new PayrollImportProfileUpsertRequest(
            profileId,
            form["name"].ToString(),
            form["sourceSystem"].ToString(),
            form["delimiter"].ToString(),
            hasHeaderRow,
            form["employeeExternalIdColumn"].ToString(),
            form["laborAmountColumn"].ToString(),
            form["fringeAmountColumn"].ToString(),
            form["taxAmountColumn"].ToString(),
            form["otherAmountColumn"].ToString(),
            form["notesColumn"].ToString(),
            form["requiredHeadersCsv"].ToString(),
            requireKnownEmployee,
            disallowDuplicates,
            requirePositiveLabor,
            isActive));

        return Results.Redirect($"/accountant/reports/payroll?profileSaved=1&selectedProfileId={profile.Id}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/payroll?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/payroll/import-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, PayrollService payroll) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var externalBatchId = form["externalBatchId"].ToString();
    var notes = form["notes"].ToString();
    var sourceChecksum = form["sourceChecksum"].ToString();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) || !DateOnly.TryParse(form["periodEnd"], out var periodEnd))
    {
        return Results.Redirect("/accountant/reports/payroll?error=invalid_period");
    }

    var rawLines = form["lines"].ToString();
    if (string.IsNullOrWhiteSpace(rawLines))
    {
        return Results.Redirect("/accountant/reports/payroll?error=no_lines");
    }

    try
    {
        if (Guid.TryParse(form["profileId"], out var profileId))
        {
            var (profile, lines) = payroll.ParseMappedExtract(profileId, rawLines);
            PayrollService.EnsureNoBlockingValidationIssues(payroll.ValidateImportLines(lines, profile));
            payroll.ImportBatch(new PayrollImportBatchRequest(
                externalBatchId,
                profile.SourceSystem,
                periodStart,
                periodEnd,
                string.IsNullOrWhiteSpace(sourceChecksum) ? null : sourceChecksum,
                string.IsNullOrWhiteSpace(notes) ? null : notes,
                lines));
        }
        else
        {
            var sourceSystem = form["sourceSystem"].ToString();
            var parsedLines = payroll.ParseManualLines(rawLines);
            PayrollService.EnsureNoBlockingValidationIssues(payroll.ValidateImportLines(parsedLines, null));

            payroll.ImportBatch(new PayrollImportBatchRequest(
                externalBatchId,
                sourceSystem,
                periodStart,
                periodEnd,
                string.IsNullOrWhiteSpace(sourceChecksum) ? null : sourceChecksum,
                string.IsNullOrWhiteSpace(notes) ? null : notes,
                parsedLines));
        }
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/payroll?error={Uri.EscapeDataString(ex.Message)}");
    }

    return Results.Redirect("/accountant/reports/payroll?saved=1");
});
app.MapPost("/api/accountant/payroll/preview-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, PayrollService payroll, PayrollImportPreviewStore previewStore, InMemoryDataStore store) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    var externalBatchId = form["externalBatchId"].ToString();
    var sourceSystem = form["sourceSystem"].ToString();
    var notes = form["notes"].ToString();
    var sourceChecksum = form["sourceChecksum"].ToString();
    if (!DateOnly.TryParse(form["periodStart"], out var periodStart) || !DateOnly.TryParse(form["periodEnd"], out var periodEnd))
    {
        return Results.Redirect("/accountant/reports/payroll?error=invalid_period");
    }

    string rawLines = string.Empty;
    var file = form.Files["extractFile"];
    if (file is not null && file.Length > 0)
    {
        using var reader = new StreamReader(file.OpenReadStream());
        rawLines = await reader.ReadToEndAsync();
    }

    if (string.IsNullOrWhiteSpace(rawLines))
    {
        rawLines = form["lines"].ToString();
    }

    if (string.IsNullOrWhiteSpace(rawLines))
    {
        return Results.Redirect("/accountant/reports/payroll?error=no_lines_or_file");
    }

    try
    {
        IReadOnlyList<PayrollImportLineRequest> lines;
        GovConMoney.Domain.Entities.PayrollImportProfile? profile = null;
        var effectiveSource = sourceSystem;
        if (Guid.TryParse(form["profileId"], out var profileId))
        {
            var parsed = payroll.ParseMappedExtract(profileId, rawLines);
            lines = parsed.Lines;
            profile = parsed.Profile;
            effectiveSource = parsed.Profile.SourceSystem;
        }
        else
        {
            lines = payroll.ParseManualLines(rawLines);
            if (string.IsNullOrWhiteSpace(effectiveSource))
            {
                effectiveSource = "Manual";
            }
        }

        var issues = payroll.ValidateImportLines(lines, profile);
        var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
        if (!Guid.TryParse(tenantIdClaim, out var tenantId))
        {
            return Results.Unauthorized();
        }
        var userByExternalId = store.Users
            .Where(x => x.TenantId == tenantId)
            .Where(x => !string.IsNullOrWhiteSpace(x.EmployeeExternalId))
            .GroupBy(x => x.EmployeeExternalId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First().UserName, StringComparer.OrdinalIgnoreCase);

        var issuesByLine = issues
            .Where(x => x.LineNumber.HasValue)
            .GroupBy(x => x.LineNumber!.Value)
            .ToDictionary(
                x => x.Key,
                x => x.OrderByDescending(i => string.Equals(i.Severity, "Error", StringComparison.OrdinalIgnoreCase))
                      .ThenByDescending(i => string.Equals(i.Severity, "Warning", StringComparison.OrdinalIgnoreCase))
                      .First());

        var validationRows = lines.Select((line, index) =>
        {
            var lineNumber = index + 1;
            if (issuesByLine.TryGetValue(lineNumber, out var issue))
            {
                return new PayrollImportValidationRow(
                    lineNumber,
                    line.EmployeeExternalId,
                    userByExternalId.TryGetValue(line.EmployeeExternalId, out var userName) ? userName : null,
                    line.LaborAmount,
                    line.FringeAmount,
                    line.TaxAmount,
                    line.OtherAmount,
                    issue.Severity,
                    issue.Message);
            }

            return new PayrollImportValidationRow(
                lineNumber,
                line.EmployeeExternalId,
                userByExternalId.TryGetValue(line.EmployeeExternalId, out var mappedUser) ? mappedUser : null,
                line.LaborAmount,
                line.FringeAmount,
                line.TaxAmount,
                line.OtherAmount,
                "OK",
                "Ready to import.");
        }).ToList();

        var summary = issues
            .GroupBy(x => x.Severity)
            .Select(x => new PayrollImportValidationSummary(x.Key, $"{x.Key}: {x.Count()} issue(s)", x.Count()))
            .ToList();

        foreach (var issue in issues.Where(x => !x.LineNumber.HasValue))
        {
            summary.Add(new PayrollImportValidationSummary(issue.Severity, issue.Message, 1));
        }

        var hasBlockingErrors = issues.Any(x => string.Equals(x.Severity, "Error", StringComparison.OrdinalIgnoreCase));

        var token = previewStore.Save(new PayrollImportPreview(
            externalBatchId,
            effectiveSource,
            periodStart,
            periodEnd,
            string.IsNullOrWhiteSpace(sourceChecksum) ? null : sourceChecksum,
            string.IsNullOrWhiteSpace(notes) ? null : notes,
            lines,
            validationRows,
            summary,
            hasBlockingErrors));

        return Results.Redirect($"/accountant/reports/payroll?previewToken={token}");
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/payroll?error={Uri.EscapeDataString(ex.Message)}");
    }
});
app.MapPost("/api/accountant/payroll/import-preview-form", [Authorize(Policy = "RequireAccountant")] async (HttpContext httpContext, PayrollService payroll, PayrollImportPreviewStore previewStore) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    if (!Guid.TryParse(form["previewToken"], out var token))
    {
        return Results.Redirect("/accountant/reports/payroll?error=invalid_preview_token");
    }

    var preview = previewStore.Get(token);
    if (preview is null)
    {
        return Results.Redirect("/accountant/reports/payroll?error=preview_expired");
    }

    if (preview.HasBlockingErrors)
    {
        return Results.Redirect($"/accountant/reports/payroll?previewToken={token}&error=preview_has_errors");
    }

    try
    {
        payroll.ImportBatch(new PayrollImportBatchRequest(
            preview.ExternalBatchId,
            preview.SourceSystem,
            preview.PeriodStart,
            preview.PeriodEnd,
            preview.SourceChecksum,
            preview.Notes,
            preview.Lines));
        previewStore.Remove(token);
    }
    catch (DomainRuleException ex)
    {
        return Results.Redirect($"/accountant/reports/payroll?error={Uri.EscapeDataString(ex.Message)}");
    }

    return Results.Redirect("/accountant/reports/payroll?saved=1");
});
app.MapGet("/api/accountant/payroll/preview-issues-csv", [Authorize(Policy = "RequireAccountant")] (Guid previewToken, bool includeWarnings, PayrollImportPreviewStore previewStore) =>
{
    var preview = previewStore.Get(previewToken);
    if (preview is null)
    {
        return Results.NotFound("Preview token not found or expired.");
    }

    var rows = preview.ValidationRows
        .Where(x => !string.Equals(x.Severity, "OK", StringComparison.OrdinalIgnoreCase))
        .Where(x => includeWarnings || string.Equals(x.Severity, "Error", StringComparison.OrdinalIgnoreCase))
        .Select(x => new
        {
            x.LineNumber,
            x.Severity,
            x.EmployeeExternalId,
            x.MatchedUserName,
            x.LaborAmount,
            x.FringeAmount,
            x.TaxAmount,
            x.OtherAmount,
            x.Message
        })
        .ToList();

    return Results.Text(ExportService.ToCsv(rows), "text/csv");
});

app.MapGet("/api/accountant/expenses/categories-view", [Authorize(Policy = "RequireAccountant")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var userById = store.Users.Where(x => x.TenantId == tenantId).ToDictionary(x => x.Id, x => x.UserName);
    var timesheets = store.Timesheets.Where(x => x.TenantId == tenantId).ToDictionary(x => x.Id);
    var chargeCodes = store.ChargeCodes.Where(x => x.TenantId == tenantId).ToDictionary(x => x.Id, x => x.Code);

    var expenseRows = store.TimesheetExpenses
        .Where(x => x.TenantId == tenantId && x.Status != ExpenseStatus.Voided)
        .Where(x => timesheets.ContainsKey(x.TimesheetId))
        .ToList();

    var rows = expenseRows
        .Select(x =>
        {
            var timesheet = timesheets[x.TimesheetId];
            return new
            {
                x.Id,
                x.TimesheetId,
                Employee = userById.TryGetValue(timesheet.UserId, out var employee) ? employee : timesheet.UserId.ToString(),
                PeriodStart = timesheet.PeriodStart,
                PeriodEnd = timesheet.PeriodEnd,
                TimesheetStatus = timesheet.Status.ToString(),
                x.ExpenseDate,
                ChargeCode = chargeCodes.TryGetValue(x.ChargeCodeId, out var code) ? code : x.ChargeCodeId.ToString(),
                x.Amount,
                x.Category,
                x.Description,
                ExpenseStatus = x.Status.ToString(),
                AccountingCategory = x.AccountingCategory.ToString()
            };
        })
        .OrderByDescending(x => x.PeriodEnd)
        .ThenByDescending(x => x.ExpenseDate)
        .ToList();
    return Results.Json(rows);
});

app.MapPost("/api/accountant/expenses/{expenseId:guid}/accounting-category-form", [Authorize(Policy = "RequireAccountant")] async (Guid expenseId, HttpContext httpContext, TimesheetService service) =>
{
    var form = await httpContext.Request.ReadFormAsync();
    _ = Enum.TryParse<ExpenseAccountingCategory>(form["accountingCategory"], out var accountingCategory);
    var reason = form["reason"].ToString();
    service.AssignExpenseAccountingCategory(expenseId, accountingCategory == 0 ? ExpenseAccountingCategory.Unassigned : accountingCategory, reason);
    return Results.Redirect("/accountant/expenses/categories?saved=1");
});

app.MapGet("/api/admin/users", [Authorize(Policy = "RequireAdmin")] async (HttpContext httpContext, InMemoryDataStore store, UserManager<GovConIdentityUser> userManager) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var users = new List<object>();
    foreach (var appUser in store.Users.Where(x => x.TenantId == tenantId).OrderBy(x => x.UserName))
    {
        var identity = await userManager.FindByIdAsync(appUser.Id.ToString());
        var roles = identity is null ? appUser.Roles : await userManager.GetRolesAsync(identity);
        users.Add(new
        {
            appUser.Id,
            appUser.UserName,
            appUser.Email,
            appUser.EmployeeExternalId,
            Roles = roles,
            MfaEnabled = identity?.TwoFactorEnabled ?? appUser.MfaEnabled,
            PasskeyRequired = identity?.PasskeyRequired ?? appUser.PasskeyRequired,
            IsDisabled = identity?.LockoutEnd.HasValue == true && identity.LockoutEnd > DateTimeOffset.UtcNow
        });
    }

    return Results.Json(users);
});

app.MapGet("/api/admin/enrollments", [Authorize(Policy = "RequireAdmin")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.EnrollmentRequests
        .Where(x => x.TenantId == tenantId)
        .OrderByDescending(x => x.SubmittedAtUtc)
        .ToList();
    return Results.Json(rows);
});

app.MapGet("/api/compliance/contracts-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var contracts = store.Contracts.Where(x => x.TenantId == tenantId)
        .Select(c => new
        {
            c.Id,
            c.ContractNumber,
            c.Name,
            c.ContractType,
            c.RequiresClinTracking,
            c.BudgetAmount,
            c.BaseYearStartDate,
            c.BaseYearEndDate,
            TaskOrderCount = store.TaskOrders.Count(t => t.ContractId == c.Id),
            PricingCount = store.ContractPricings.Count(p => p.ContractId == c.Id),
            OptionYearCount = store.ContractOptionYears.Count(o => o.ContractId == c.Id)
        })
        .ToList();
    return Results.Json(contracts);
});
app.MapGet("/api/compliance/chargecodes-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = (from cc in store.ChargeCodes
                where cc.TenantId == tenantId
                join wbs in store.WbsNodes on cc.WbsNodeId equals wbs.Id
                join clin in store.Clins on wbs.ClinId equals clin.Id
                join task in store.TaskOrders on clin.TaskOrderId equals task.Id
                join contract in store.Contracts on task.ContractId equals contract.Id
                select new
                {
                    cc.Id,
                    ContractNumber = contract.ContractNumber,
                    ContractType = contract.ContractType.ToString(),
                    TaskOrder = task.Number,
                    Clin = clin.Number,
                    Wbs = wbs.Code,
                    ChargeCode = cc.Code,
                    cc.IsActive
                }).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/compliance/pricing-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = (from p in store.ContractPricings
                where p.TenantId == tenantId
                join c in store.Contracts on p.ContractId equals c.Id
                select new
                {
                    ContractId = c.Id,
                    c.ContractNumber,
                    p.LaborCategory,
                    Site = p.Site.ToString(),
                    p.BaseHourlyRate,
                    p.EscalationPercent,
                    p.FeePercent
                }).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/compliance/contracts-burndown-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var contractById = store.Contracts
        .Where(x => x.TenantId == tenantId)
        .ToDictionary(x => x.Id);
    var taskOrderById = store.TaskOrders
        .Where(x => x.TenantId == tenantId)
        .ToDictionary(x => x.Id);
    var clinById = store.Clins
        .Where(x => x.TenantId == tenantId)
        .ToDictionary(x => x.Id);
    var wbsById = store.WbsNodes
        .Where(x => x.TenantId == tenantId)
        .ToDictionary(x => x.Id);
    var chargeCodeToContractId = store.ChargeCodes
        .Where(x => x.TenantId == tenantId)
        .ToDictionary(
            x => x.Id,
            x =>
            {
                if (!wbsById.TryGetValue(x.WbsNodeId, out var wbsNode))
                {
                    return (Guid?)null;
                }

                if (!clinById.TryGetValue(wbsNode.ClinId, out var clin))
                {
                    return (Guid?)null;
                }

                if (!taskOrderById.TryGetValue(clin.TaskOrderId, out var taskOrder))
                {
                    return (Guid?)null;
                }

                return taskOrder.ContractId;
            });

    var averageRateByContract = store.ContractPricings
        .Where(x => x.TenantId == tenantId)
        .GroupBy(x => x.ContractId)
        .ToDictionary(x => x.Key, x => x.Average(p => p.BaseHourlyRate));

    var lines = store.TimesheetLines
        .Where(x => x.TenantId == tenantId)
        .OrderBy(x => x.WorkDate)
        .ToList();

    var lineGroups = lines
        .Select(x =>
        {
            if (!chargeCodeToContractId.TryGetValue(x.ChargeCodeId, out var contractId) || contractId is null)
            {
                return null;
            }

            var rate = averageRateByContract.TryGetValue(contractId.Value, out var avgRate) ? avgRate : 0m;
            var amount = (x.Minutes / 60m) * rate;
            return new { ContractId = contractId.Value, x.WorkDate, Amount = amount };
        })
        .Where(x => x is not null)
        .Select(x => x!)
        .GroupBy(x => x.ContractId)
        .ToDictionary(x => x.Key, x => x.GroupBy(g => g.WorkDate).OrderBy(g => g.Key).ToList());

    var rows = contractById.Values.Select(contract =>
    {
        var cumulative = 0m;
        var points = new List<object>();
        if (lineGroups.TryGetValue(contract.Id, out var dateGroups))
        {
            foreach (var dateGroup in dateGroups)
            {
                cumulative += dateGroup.Sum(v => v.Amount);
                points.Add(new
                {
                    Date = dateGroup.Key,
                    SpentAmount = Math.Round(cumulative, 2),
                    RemainingAmount = Math.Round(contract.BudgetAmount - cumulative, 2)
                });
            }
        }

        if (points.Count == 0)
        {
            points.Add(new
            {
                Date = DateOnly.FromDateTime(DateTime.UtcNow),
                SpentAmount = 0m,
                RemainingAmount = contract.BudgetAmount
            });
        }

        return new
        {
            ContractId = contract.Id,
            BudgetAmount = contract.BudgetAmount,
            SpentAmount = Math.Round(cumulative, 2),
            RemainingAmount = Math.Round(contract.BudgetAmount - cumulative, 2),
            Points = points
        };
    }).ToList();

    return Results.Json(rows);
});

app.MapGet("/api/compliance/assignments-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var assignments = store.Assignments.Where(x => x.TenantId == tenantId)
        .Select(a => new
        {
            a.Id,
            UserName = store.Users.FirstOrDefault(u => u.Id == a.UserId)!.UserName,
            ChargeCode = store.ChargeCodes.FirstOrDefault(c => c.Id == a.ChargeCodeId)!.Code,
            a.EffectiveStartDate,
            a.EffectiveEndDate,
            a.SupervisorOverrideAllowed
        })
        .ToList();
    return Results.Json(assignments);
});
app.MapGet("/api/compliance/supervisors-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.PersonnelProfiles.Where(x => x.TenantId == tenantId).Select(p => new
    {
        Employee = store.Users.FirstOrDefault(x => x.Id == p.UserId)!.UserName,
        Supervisor = p.SupervisorUserId.HasValue ? store.Users.FirstOrDefault(x => x.Id == p.SupervisorUserId.Value)!.UserName : "(none)"
    }).ToList();
    return Results.Json(rows);
});

app.MapGet("/api/compliance/periods-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var periods = store.AccountingPeriods.Where(x => x.TenantId == tenantId).OrderByDescending(x => x.StartDate).ToList();
    return Results.Json(periods);
});
app.MapGet("/api/compliance/allowability-view", [Authorize(Policy = "RequireCompliance")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.AllowabilityRules.Where(x => x.TenantId == tenantId)
        .Select(x => new { CostType = x.CostType.ToString(), x.RuleName, x.RuleDescription, x.RequiresComment })
        .ToList();
    return Results.Json(rows);
});

app.MapGet("/api/timereporter/status-view", [Authorize(Policy = "RequireTimeReporter")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var userIdClaim = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(userIdClaim, out var userId))
    {
        return Results.Unauthorized();
    }

    var rows = store.Timesheets.Where(x => x.UserId == userId).OrderByDescending(x => x.PeriodEnd).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/timereporter/timesheets/{timesheetId:guid}/lines-view", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, HttpContext httpContext, InMemoryDataStore store) =>
{
    var userIdClaim = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(userIdClaim, out var userId))
    {
        return Results.Unauthorized();
    }

    var ownsTimesheet = store.Timesheets.Any(x => x.Id == timesheetId && x.UserId == userId);
    if (!ownsTimesheet)
    {
        return Results.NotFound();
    }

    var rows = store.TimesheetLines
        .Where(x => x.TimesheetId == timesheetId)
        .OrderBy(x => x.WorkDate)
        .ThenBy(x => x.Id)
        .Select(x => new { x.Id, x.WorkDate, x.ChargeCodeId, x.Minutes, CostType = x.CostType.ToString(), x.Comment })
        .ToList();
    return Results.Json(rows);
});
app.MapGet("/api/timereporter/timesheets/{timesheetId:guid}/work-notes-view", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, HttpContext httpContext, InMemoryDataStore store) =>
{
    var userIdClaim = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(userIdClaim, out var userId))
    {
        return Results.Unauthorized();
    }

    var ownsTimesheet = store.Timesheets.Any(x => x.Id == timesheetId && x.UserId == userId);
    if (!ownsTimesheet)
    {
        return Results.NotFound();
    }

    var rows = store.TimesheetWorkNotes
        .Where(x => x.TimesheetId == timesheetId)
        .OrderByDescending(x => x.CreatedAtUtc)
        .ToList();
    return Results.Json(rows);
});
app.MapGet("/api/timereporter/timesheets/{timesheetId:guid}/expenses-view", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, HttpContext httpContext, InMemoryDataStore store) =>
{
    var userIdClaim = httpContext.User.FindFirstValue("domain_user_id");
    if (!Guid.TryParse(userIdClaim, out var userId))
    {
        return Results.Unauthorized();
    }

    var ownsTimesheet = store.Timesheets.Any(x => x.Id == timesheetId && x.UserId == userId);
    if (!ownsTimesheet)
    {
        return Results.Forbid();
    }

    var rows = store.TimesheetExpenses
        .Where(x => x.TimesheetId == timesheetId)
        .OrderByDescending(x => x.ExpenseDate)
        .ToList();
    return Results.Json(rows);
});
app.MapGet("/api/timereporter/timesheets/{timesheetId:guid}/weekly-status-view", [Authorize(Policy = "RequireTimeReporter")] (Guid timesheetId, HttpContext httpContext, InMemoryDataStore store) =>
{
    var userIdClaim = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(userIdClaim, out var userId))
    {
        return Results.Unauthorized();
    }

    var ownsTimesheet = store.Timesheets.Any(x => x.Id == timesheetId && x.UserId == userId);
    if (!ownsTimesheet)
    {
        return Results.NotFound();
    }

    var report = store.WeeklyStatusReports.SingleOrDefault(x => x.TimesheetId == timesheetId);
    return Results.Json(report);
});

app.MapGet("/api/timereporter/corrections-view", [Authorize(Policy = "RequireTimeReporter")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var userIdClaim = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(userIdClaim, out var userId))
    {
        return Results.Unauthorized();
    }

    var timesheetIds = store.Timesheets.Where(x => x.UserId == userId).Select(x => x.Id).ToHashSet();
    var rows = store.CorrectionRequests.Where(x => timesheetIds.Contains(x.TimesheetId)).OrderByDescending(x => x.RequestedAtUtc).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/timereporter/versions-view", [Authorize(Policy = "RequireTimeReporter")] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var userIdClaim = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(userIdClaim, out var userId))
    {
        return Results.Unauthorized();
    }

    var timesheetIds = store.Timesheets.Where(x => x.UserId == userId).Select(x => x.Id).ToHashSet();
    var rows = store.TimesheetVersions.Where(x => timesheetIds.Contains(x.TimesheetId)).OrderByDescending(x => x.CreatedAtUtc).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/lookups/contracts", [Authorize] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.Contracts.Where(x => x.TenantId == tenantId).Select(x => new { x.Id, x.ContractNumber, x.RequiresClinTracking }).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/lookups/taskorders", [Authorize] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.TaskOrders.Where(x => x.TenantId == tenantId).Select(x => new { x.Id, x.Number, x.ContractId, x.RequiresClinTracking }).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/lookups/clins", [Authorize] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.Clins.Where(x => x.TenantId == tenantId).Select(x => new { x.Id, x.Number, x.TaskOrderId }).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/lookups/wbs", [Authorize] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.WbsNodes.Where(x => x.TenantId == tenantId).Select(x => new { x.Id, x.Code, x.ClinId, x.ParentWbsNodeId }).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/lookups/users", [Authorize] (HttpContext httpContext, InMemoryDataStore store, string? role) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var users = store.Users.Where(x => x.TenantId == tenantId).ToList();
    if (!string.IsNullOrWhiteSpace(role))
    {
        users = users.Where(x => x.Roles.Contains(role, StringComparer.OrdinalIgnoreCase)).ToList();
    }

    var rows = users.Select(x => new { x.Id, x.UserName, x.EmployeeExternalId, Roles = x.Roles }).ToList();
    return Results.Json(rows);
});
app.MapGet("/api/lookups/chargecodes", [Authorize] (HttpContext httpContext, InMemoryDataStore store) =>
{
    var tenantIdClaim = httpContext.User.FindFirstValue("tenant_id");
    if (!Guid.TryParse(tenantIdClaim, out var tenantId))
    {
        return Results.Unauthorized();
    }

    var rows = store.ChargeCodes.Where(x => x.TenantId == tenantId)
        .Select(x => new { x.Id, x.Code, CostType = x.CostType.ToString(), x.IsActive })
        .ToList();
    return Results.Json(rows);
});
app.MapGet("/api/lookups/tenants", (InMemoryDataStore store) =>
{
    var rows = store.Tenants.Select(x => new { x.Id, x.Name }).ToList();
    return Results.Json(rows);
});

app.MapRazorComponents<GovConMoney.Web.Components.App>().AddInteractiveServerRenderMode();

app.Run();

public sealed record PasskeyRegisterCompleteRequest(string FlowId, AuthenticatorAttestationRawResponse Attestation);
public sealed record PasskeyLoginOptionsRequest(string Username);
public sealed record PasskeyLoginCompleteRequest(string FlowId, AuthenticatorAssertionRawResponse Assertion);

