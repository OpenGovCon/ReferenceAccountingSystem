## Reference Accounting System (DCAA / DFARS 252.242-7006)

This repository contains an open reference implementation of an accounting system aligned with DFARS 252.242-7006 and DCAA accounting system adequacy expectations.


It is designed to be:

- clause-mapped

- test-validated

- evidence-generating

- auditor-readable

## Important Disclaimer

DCAA does not "approve software."

DCAA evaluates whether an organization’s accounting system is adequate based on its implementation, configuration, accounting policies, and operational discipline.

This repository provides a reference implementation of controls and evidence generation, but does not guarantee audit outcomes.

See `DISCLAIMER.md`.
## What This Project Provides
- Timekeeping workflow controls (daily entry rules, approvals, corrections)
- Direct / indirect / unallowable segregation
- Indirect pool rate calculation + burden application + rerating support
- General ledger control (double-entry)
- Trial balance and subledger-to-GL reconciliation
- Period close workflow
- Billing generation from allowable incurred costs
- Ceiling / funding limit enforcement
- Billed-to-booked reconciliation reporting
- Maker-checker workflow for adjusting journal entries
- Automated evidence binder generation ("audit binder")
## Evidence Binder Output
The system produces deterministic compliance artifacts under:
`GovConMoney.Tests/Runner/AuditBinderOutput/<timestamp_guid>/`

This binder is intended to support internal audit preparation and DCAA walkthroughs.
## Clause-to-Control Matrix
See:
`/compliance/dfars-252-242-7006/clause-to-control-matrix.md`
This matrix maps DFARS criteria to:
- system controls
- code references
- test cases
- evidence outputs
## License
This project is licensed under AGPLv3. See `LICENSE`.
A commercial license may be available. See `COMMERCIAL-LICENSE.md`.
## Contributions
See `CONTRIBUTING.md`.
All contributions must include:
- automated tests
- evidence output impact documentation
- updates to the clause-to-control matrix when applicable
