# GovConMoney

GovConMoney is a multi-tenant government contractor accounting and timekeeping system scaffold targeting .NET 10 and Blazor Server.

## Key Design Decisions
- Blazor mode: Blazor Server for controlled server-side security and centralized auditability.
- Identity type: cookie auth with role policies and seeded users; MFA/passkey flags are modeled and passkey endpoints are implemented.
- DB choice: SQL Server intended for production, with PostgreSQL DDL included for schema portability and audit review.
- Multi-tenant approach: `tenant_id` on all business entities with repository query scoping.

## Solution Tree
- `GovConMoney.Domain`
- `GovConMoney.Application`
- `GovConMoney.Infrastructure`
- `GovConMoney.Web`
- `GovConMoney.Tests`

## Features Implemented
- Compliance hierarchy and assignment controls.
- Contract pricing by labor category including escalation, fee, and government vs contractor site separation.
- Contract types: fixed value, IDIQ, cost-plus-fee.
- Charge code lifecycle controls (active/inactive).
- Supervisor relationship management and accounting period open/close controls.
- Out-of-window charging with supervisor override approval workflow.
- Allowability rules for cost type tagging.
- Self-enrollment request page with mandatory admin approval before user activation.
- Login page for seeded and admin-approved users.
- Forensic transaction logging (who/when/what) backed by append-only audit events.
- Timesheet draft/submit/approve/correction immutable workflow.
- Labor distribution, project summary, compliance, and audit reporting services.
- CSV/JSON export utilities.
- Role-routed portals for Admin, Compliance, Time Reporter, Accountant.
- Passkey registration/assertion endpoints (service-backed metadata storage).`r`n- Portal action workflows use API/form endpoints for login, enrollment approval, admin controls, time entry submit/approve/correct, supervisor overrides, and report exports.`r`n- Read-side snapshot APIs are exposed for Admin, Compliance, and TimeReporter views.
- Seed data for tenant, users, contract/task order/charge code assignment.

## Run
1. `set DOTNET_CLI_HOME=c:\core\gitroot\GovConMoney\src`
2. `dotnet build GovConMoney.slnx`
3. `dotnet run --project GovConMoney.Web`
4. `dotnet run --project GovConMoney.Tests`

## Database Bootstrap Notes
- The app initializes two EF Core contexts on startup:
  - `GovConMoneyDbContext` (primary domain data) uses migrations.
  - `GovConIdentityDbContext` (ASP.NET Identity data) currently uses `EnsureCreated()`.
- Important nuance for hosted/shared SQL Server:
  - `EnsureCreated()` does not use migrations and can no-op when the database already exists.
  - If `Primary` and `Identity` point to the same existing database, Identity tables (for example `AspNetUsers`, `AspNetRoles`) may not be created.
- Recommended production setup:
  - Add and apply migrations for `GovConIdentityDbContext`.
  - Use `Database.Migrate()` for Identity startup initialization.
  - Prefer separate databases for `Primary` and `Identity` connection strings.
- If tables still do not appear after that, verify SQL permissions for the runtime login (it must be able to create/alter tables).

## Seeded Users
Default seeded accounts:
- `admin`
- `compliance`
- `accountant`
- `supervisor`
- `timereporter`

Default seed password (for all seeded users):
- `TempPass#2026!`

Login options:
- Web UI: `/auth/login`
- API form login: `POST /api/login-form` with form fields `username` and `password`

## Security Warning: Change Seed Credentials Before Production
- The default seed password is a bootstrap-only credential and must be changed before any real deployment.
- Do not publish or run an environment with unchanged seeded credentials.
- Rotate/remove seed users if not required in your environment.

Where to change seed credential behavior in code:
- `engine-core/GovConMoney.Web/Security/IdentitySeed.cs`
  - `SeedPassword` constant controls the seeded default password.
- `engine-core/GovConMoney.Web/Program.cs`
  - `await IdentitySeed.InitializeAsync(...)` controls startup seeding.
- `engine-core/GovConMoney.Web/Components/Pages/Security/Login.razor`
  - Contains the login-page seed password note shown to users.
- `engine-core/GovConMoney.Web/Components/Pages/Admin/EnrollmentApprovals.razor`
  - Uses `IdentitySeed.SeedPassword` when creating approved users.
