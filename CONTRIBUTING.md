# Contributing Guide



Thank you for your interest in contributing to the OpenGovCon Reference Accounting System.



This repository exists to provide a clause-mapped, test-validated, evidence-generating

reference implementation aligned to DFARS 252.242-7006 and DCAA accounting system

adequacy expectations.



This is not a typical "open source app." Contributions must preserve compliance integrity.



---



## 1. Guiding Rule: Evidence Comes First



Every compliance-relevant feature must include:

- deterministic behavior

- automated tests

- evidence binder outputs

- documentation updates



If a feature cannot be validated through testable evidence output, it is not complete.



---



## 2. Required Contribution Standards



All pull requests must include:



### A) Tests

- New controls must have tests in `GovConMoney.Tests`

- Tests must be deterministic (no random output, no time-dependent flakiness)

- Tests must produce exportable artifacts when appropriate



### B) Clause-to-Control Matrix Updates

If your change affects DFARS compliance behavior, you must update:



`/compliance/dfars-252-242-7006/clause-to-control-matrix.md`



### C) Evidence Binder Impact

If your change affects exported evidence, document it in:

- the PR description

- or the evidence spec file if applicable



### D) Audit Trail Requirements

All compliance-critical workflow transitions must produce `AuditEvent` entries.



---



## 3. Compliance Scope Rules



This project is designed around DFARS 252.242-7006 and common DCAA adequacy criteria.



Contributions must not:

- weaken enforcement of timekeeping approvals

- allow deletion or mutation of posted accounting records

- remove maker-checker workflows for compliance-critical actions

- introduce "silent bypasses" of controls



If you propose a relaxation of controls, you must justify it explicitly.



---



## 4. Code Organization



Use the project boundaries as intended:



- **GovConMoney.Domain**

&nbsp; - entities and enums only

&nbsp; - no business logic

- **GovConMoney.Application**

&nbsp; - services and compliance logic

&nbsp; - validation engines and workflows

- **GovConMoney.Infrastructure**

&nbsp; - EF mappings, persistence enforcement, query filters

- **GovConMoney.Web**

&nbsp; - UI, endpoints, auth policy enforcement

- **GovConMoney.Tests**

&nbsp; - evidence harness and compliance test suite



---



## 5. Branch and PR Process



- Create a branch from `main`

- Open a pull request

- Ensure CI tests pass

- Ensure compliance artifacts are updated

- Maintainers may request changes to ensure audit defensibility



---



## 6. Commit Message Expectations



Use meaningful commit messages. Example:



- `Add billed-to-booked reconciliation report`

- `Enforce daily entry grace policy`

- `Add maker-checker approval workflow for indirect rates`



Avoid meaningless messages like:

- `fix stuff`

- `changes`

- `cleanup`



---



## 7. Security and Vulnerabilities



If you discover a security issue, do NOT open a public issue.



Instead follow `SECURITY.md`.



---



## 8. License and Contributor Agreement



This repository is licensed under AGPLv3.



By submitting a contribution, you agree that your contribution is licensed

under the repository license.



Some contributions may require signing a Contributor License Agreement (CLA).

See `CLA.md`.



---



## 9. Code of Conduct



By participating in this project you agree to follow `CODE_OF_CONDUCT.md`.



