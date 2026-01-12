# GuardianProtocol

### Automated Compliance with Dynamic Policies for the Stacks Blockchain

---

## Executive Summary

I have engineered **GuardianProtocol**, a sophisticated Clarity smart contract designed to bridge the gap between decentralized finance (DeFi) and regulatory necessity. As blockchain ecosystems evolve, the requirement for robust, transparent, and automated compliance frameworks becomes paramount. **GuardianProtocol** provides a programmable infrastructure for enforcing multi-tier compliance policies, managing user reputations, and maintaining an immutable audit trail of regulatory standing and violations.

Through the use of dynamic policy enforcement, I have created a system that allows for real-time adjustment of compliance requirements without the need for frequent contract migrations. This protocol serves as a foundational layer for regulated DAOs, security token offerings (STOs), and permissioned liquidity pools.

---

## Table of Contents

1. Architecture Overview
2. Core Functional Modules
3. Technical Specification
4. Comprehensive Function Analysis (Private & Public)
5. Compliance Tier System
6. Administrative Governance
7. Operational Workflow
8. Security & Assertions
9. Integration Guide
10. MIT License

---

## Architecture Overview

I designed the architecture of **GuardianProtocol** around the principle of "Defense in Depth." The system does not rely on a single check; instead, it utilizes a multi-layered verification process that evaluates identity standing, reputation metrics, temporal validity, and explicit authorization.

---

## Comprehensive Function Analysis

In this section, I provide an intense deep dive into the logic gatekeeping the protocol. I have structured these functions to ensure that state-changing operations are strictly guarded while read-only verifications remain highly performant.

### Internal Logic (Private Functions)

These functions are the "engine room" of the contract. I have kept them private to ensure that the internal validation logic cannot be bypassed or externally manipulated.

* **`is-contract-owner`**: I use this as the primary administrative gate. It compares the `tx-sender` against a hardcoded constant set at deployment.
* **`is-authorized-officer`**: This function performs a lookup in the `authorized-officers` map. I designed it to return `false` by default via `default-to`, ensuring that if a principal isn't found, they are automatically denied access.
* **`is-valid-compliance-level`**: A safety utility I implemented to ensure no one accidentally (or maliciously) assigns a compliance level outside the range of  to .
* **`is-policy-active`**: This is a critical temporal check. It doesn't just check the `active` boolean; I also programmed it to compare the current `block-height` against the policy's `expiration-height`. This ensures policies "self-expire" without requiring manual intervention.
* **`user-meets-policy-requirements`**: This is the core logic aggregator. I used nested `match` statements here to verify five distinct conditions: compliance level, reputation score, violation count, blacklist status, and verification expiry. If any single check fails, the entire transaction is rejected.

### Interface Layer (Public Functions)

These functions constitute the API of the contract. I have optimized them for clarity and security.

* **`register-user`**: This is the entry point for new participants. I included a check to ensure users cannot be "re-registered," which prevents resetting reputation scores or violation counts by mistake.
* **`create-policy`**: I designed this to allow Officers to define the rules of engagement. It captures metadata (name) and hard constraints (reputation/levels). I ensured that the `next-policy-id` increments automatically to maintain a unique index.
* **`verify-compliance`**: A "read-style" public function. While it consumes gas, it allows other contracts to query a user's status without triggering the more complex enforcement logic.
* **`record-violation`**: This allows Officers to penalize bad actors. I designed this to be "sticky"—once a violation is recorded, it increments the user's global `violation-count`, which may automatically lock them out of other policies that have low violation thresholds.
* **`update-user-compliance`**: The primary tool for KYC providers. I programmed this to allow for a `verification-duration`, meaning a user’s "Verified" status is only temporary, forcing periodic re-evaluation.
* **`approve-user-for-policy`**: I added this for "High-Touch" compliance. Even if a user meets general criteria, some policies may require manual "Officer Approval." This function creates that specific link.
* **`enforce-compliance-with-approval`**: This is the most complex function in the suite. I designed it to perform a "Full Sweep." It validates the policy, the user, the temporal status, and the specific officer approval in a single atomic transaction.

---

## Technical Specification

### Constants & Error Codes

I have utilized standard Stacks error coding to ensure that off-chain interfaces can easily parse the reason for a transaction failure.

| Constant | Value | Description |
| --- | --- | --- |
| `ERR-NOT-AUTHORIZED` | `u100` | Caller lacks administrative or officer privileges. |
| `ERR-POLICY-NOT-FOUND` | `u101` | The requested Policy ID does not exist. |
| `ERR-USER-NOT-COMPLIANT` | `u103` | User fails basic compliance or is blacklisted. |
| `ERR-POLICY-EXPIRED` | `u104` | The policy or verification is past its block-height. |
| `ERR-THRESHOLD-EXCEEDED` | `u105` | User has too many recorded violations. |

---

## Compliance Tier System

I have established five distinct tiers of compliance to allow for granular access control:

1. **Tier 0 (None):** Unregistered or restricted users.
2. **Tier 1 (Basic):** Standard registered users; minimal KYC.
3. **Tier 2 (Standard):** Verified users eligible for most DeFi activities.
4. **Tier 3 (Advanced):** High-net-worth or institutional grade verification.
5. **Tier 4 (Premium):** Maximum trust level for sensitive governance or large-scale transfers.

---

## Security & Assertions

I have integrated several safety "fail-safes" to protect the integrity of the protocol:

* **Duration Caps**: No policy or verification can exceed  blocks.
* **Violation Limits**: A hard cap on violation counts () prevents overflow.
* **Atomic Updates**: Global counters are updated only upon successful map insertion.

---

## Integration Guide

To integrate **GuardianProtocol** into your existing Clarity project, I recommend the following pattern:

```clarity
(extern-call! .guardian-protocol enforce-compliance-with-approval tx-sender u1 u0)

```

By placing this assertion at the start of your public functions, you ensure that only users who meet the specific requirements of Policy ID `u1` can interact with your contract logic.

---

## MIT License

Copyright (c) 2026 GuardianProtocol Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---
