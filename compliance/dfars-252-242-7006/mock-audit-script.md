\# Mock Audit Script (DCAA Walkthrough)



This document provides a structured walkthrough intended to simulate a DCAA accounting

system adequacy review.



\## Objective



Demonstrate that the accounting system:

\- enforces timekeeping controls

\- segregates direct/indirect/unallowable costs

\- accumulates costs by contract and CLIN when required

\- applies indirect rates consistently

\- posts transactions under GL control

\- supports adjusting entry approvals

\- supports billing from allowable incurred costs

\- produces reconciliation evidence



---



\## Section 1: Timekeeping Controls



1\. Select a random employee.

2\. Show the employee's timesheet for the current open period.

3\. Demonstrate:

&nbsp;  - daily entry enforcement

&nbsp;  - prevention of self-approval

&nbsp;  - correction workflow and audit trail



Evidence:

\- timesheet\_compliance.csv

\- audit\_trail.csv



---



\## Section 2: Labor Distribution



1\. Select a contract and CLIN.

2\. Show labor distribution report by:

&nbsp;  - contract

&nbsp;  - task order

&nbsp;  - CLIN

&nbsp;  - WBS

&nbsp;  - charge code



Evidence:

\- labor\_distribution.csv



---



\## Section 3: Indirect Rate Calculation



1\. Show pool totals and base totals.

2\. Show computed indirect rate.

3\. Demonstrate burden application to cost objectives.



Evidence:

\- indirect\_rate\_support.csv

\- applied\_burden\_summary.csv



---



\## Section 4: General Ledger Control



1\. Show the general journal report.

2\. Show trial balance for the period.

3\. Demonstrate that the system produces balanced postings.



Evidence:

\- general\_journal.csv

\- trial\_balance.csv



---



\## Section 5: Subledger to GL Reconciliation



1\. Show reconciliation for labor.

2\. Show reconciliation for expenses.

3\. Show reconciliation for burdens.

4\. Demonstrate that variances are explained or zero.



Evidence:

\- subledger\_gl\_tieout.csv



---



\## Section 6: Adjusting Journal Entries



1\. Create a draft adjusting journal entry.

2\. Submit for approval.

3\. Approve as a different user.

4\. Post the entry.

5\. Reverse the entry and show linkage.



Evidence:

\- adjusting\_je\_packet.csv

\- audit\_trail.csv



---



\## Section 7: Billings and Ceilings



1\. Generate a billing run for a contract.

2\. Demonstrate that unallowable costs are excluded.

3\. Demonstrate ceiling/funding enforcement.

4\. Generate billed-to-booked reconciliation.



Evidence:

\- invoices.csv

\- invoice\_lines.csv

\- billed\_to\_booked\_reconciliation.csv



---



\## Section 8: Period Close



1\. Run close validation.

2\. Demonstrate that the system prevents closing with missing approvals.

3\. Close the period.

4\. Demonstrate that postings are prevented after close.



Evidence:

\- audit\_trail.csv

\- trial\_balance.csv

\- subledger\_gl\_tieout.csv



