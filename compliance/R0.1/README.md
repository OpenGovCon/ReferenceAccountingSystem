# DFARS 252.242-7006 Compliance Package

Release certification package: `R0.1`  
Release date: `2026-02-25`  
Requirement source: `compliance/dfars.txt` (18 DFARS 252.242-7006 criteria)



This folder contains OpenGovCon's clause-mapped compliance artifacts for DFARS 252.242-7006

(Accounting System Administration).



The intent is to provide a transparent mapping between:



- DFARS accounting system criteria

- implemented system controls

- code references

- automated test evidence

- evidence binder output artifacts



## Key Files



- `clause-to-control-matrix.md`

- maps DFARS clause criteria to controls and evidence



- `evidence-spec.md`

- defines expected evidence output formats (CSV/JSON)

- defines column requirements and meaning



- `mock-audit-script.md`

- provides a DCAA-style walkthrough script

- can be used for internal audits and mock floor checks



## Important Disclaimer



DCAA does not approve software.



System adequacy is determined by:

- implementation

- accounting policies

- operational usage

- audit evidence



This repository provides a reference implementation and evidence harness only.



## Evidence Binder Output



The system generates evidence output in a deterministic folder structure such as:



`GovConMoney.Tests/Runner/AuditBinderOutput/<timestamp_guid>/`



The binder is generated through automated tests and can be used to produce

a reproducible audit evidence packet.



