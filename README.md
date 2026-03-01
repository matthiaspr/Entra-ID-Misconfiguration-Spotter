# Entra ID Misconfiguration Spotter

A lightweight CLI tool that audits Microsoft Entra ID for security misconfigurations.

## Installation

Requires [uv](https://docs.astral.sh/uv/) and Python 3.10+.

```bash
# Clone and enter the repository
git clone <repository-url>
cd Entra-ID-Misconfiguration-Spotter

# Install dependencies (run once, or after pyproject.toml changes)
uv sync
```

All `uv run` commands below should be run from this directory.

## Usage

### Authentication

You can provide credentials via CLI flags, shell environment variables, or a `.env` file.

Precedence: `CLI flags > shell environment variables > .env`

**CLI flags:**
```bash
uv run entra-spotter -t <tenant-id> -c <client-id> -s <client-secret>
```

**Environment variables:**
```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

uv run entra-spotter
```

**.env file (from current working directory):**
```bash
cat > .env << 'EOF'
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
EOF

uv run entra-spotter
```

### Running Checks

```bash
# Run all checks
uv run entra-spotter

# Run with JSON output
uv run entra-spotter --json

# Run specific checks
uv run entra-spotter --check user-consent --check sp-admin-roles

# List available checks
uv run entra-spotter --list-checks
```

## Checks

### Application & Consent

#### `user-consent` — User Consent Settings

Checks whether users can independently consent to third-party apps accessing company data. Reads `permissionGrantPoliciesAssigned` on the authorization policy. Unrestricted user consent is a common vector for illicit consent grant attacks, where a malicious app tricks a user into granting it access to organizational data.

| Result | Condition |
|--------|-----------|
| PASS | User consent is disabled (no enabling policies assigned) |
| FAIL | Users can consent to all apps (legacy default) or to apps from verified publishers |
| WARN | A custom consent policy is in use |

> **Recommendation:** Set user consent to "Do not allow user consent" in Entra ID.

#### `admin-consent-workflow` — Admin Consent Workflow

Checks whether the admin consent workflow is enabled with designated reviewers so app consent requests go through approval. Without this workflow, users who are blocked from consenting have no way to request access, leading to shadow IT or support burden on admins.

| Result | Condition |
|--------|-----------|
| PASS | Enabled with at least one reviewer configured |
| FAIL | Workflow is disabled |
| WARN | Enabled but no reviewers configured |

> **Recommendation:** Enable the admin consent workflow and ensure at least one reviewer is configured.

#### `sp-admin-roles` — Service Principals in Privileged Roles

Checks whether any service principals hold one of the 14 privileged directory roles. Service principals with admin roles can perform privileged operations without interactive sign-in or MFA.

| Result | Condition |
|--------|-----------|
| PASS | No service principals in privileged roles |
| WARN | One or more service principals found (lists each with role name) |

> **Recommendation:** Review whether these service principals require privileged access.

#### `sp-graph-roles` — Service Principals with Sensitive Graph Permissions

Checks whether any service principals hold sensitive MS Graph application permissions: `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, or `UserAuthenticationMethod.ReadWrite.All`. These permissions allow modifying role assignments, granting app permissions, or resetting authentication methods.

| Result | Condition |
|--------|-----------|
| PASS | No service principals have these permissions |
| WARN | One or more found (lists each with permission name) |

> **Recommendation:** Review whether these service principals require these powerful permissions.

#### `sp-multiple-secrets` — Service Principals with Multiple Credentials

Checks whether any service principals have 2+ credentials (client secrets or certificates) across both the SP object and its linked app registration. Multiple active credentials increase attack surface and suggest rotation issues.

| Result | Condition |
|--------|-----------|
| PASS | All service principals have 0 or 1 credential |
| WARN | One or more have 2+ credentials (lists count, type, and source) |

> **Recommendation:** Remove unnecessary secrets or certificates.

### Conditional Access

#### `legacy-auth-blocked` — Legacy Authentication Blocked

Checks whether an enforced CA policy blocks legacy authentication protocols (`Exchange ActiveSync` and `Other clients`) for all users and all cloud apps. Legacy protocols don't support MFA.

| Result | Condition |
|--------|-----------|
| PASS | Enforced blocking policy exists with no exclusions |
| FAIL | No matching policy exists, or policy is only in report-only mode |
| WARN | Enforced policy exists but has user, group, or application exclusions |

> **Recommendation:** Create or enable a CA policy blocking legacy authentication for all cloud apps.

#### `device-code-blocked` — Device Code Flow Blocked

Checks whether an enforced CA policy blocks device code flow for all users and all cloud apps. Device code flow is commonly exploited in phishing attacks.

| Result | Condition |
|--------|-----------|
| PASS | Enforced blocking policy exists with no exclusions |
| FAIL | No matching policy exists, or policy is only in report-only mode |
| WARN | Enforced policy exists but has exclusions |

> **Recommendation:** Create or enable a CA policy blocking device code flow.

#### `break-glass-exclusion` — Emergency Access Account Exclusions

Checks whether at least 2 user accounts are excluded from every enabled CA policy. Emergency access (break-glass) accounts must bypass all policies to prevent tenant lockout during misconfiguration or outage.

| Result | Condition |
|--------|-----------|
| PASS | 2+ user accounts excluded from all enabled policies |
| FAIL | No user accounts are universally excluded |
| WARN | Only 1 account excluded, or no enabled CA policies exist |

> **Recommendation:** Create at least 2 emergency access accounts and exclude them from all CA policies.

### Privileged Role Security

#### `privileged-roles-mfa` — MFA Required for Privileged Roles

Checks whether enforced CA policies require MFA for all 14 privileged directory roles across all cloud apps. Privileged accounts are high-value targets — compromising one grants broad control over the tenant. MFA significantly reduces the risk of credential-based attacks. Multiple policies can collectively cover all roles.

| Result | Condition |
|--------|-----------|
| PASS | All 14 roles covered by enforced policies with no exclusions |
| FAIL | No matching policy, only report-only policies, or some roles not covered (lists uncovered roles) |
| WARN | All roles covered but policies have user/group exclusions |

> **Recommendation:** Create or enable CA policies requiring MFA for all privileged roles.

#### `privileged-roles-phishing-resistant-mfa` — Phishing-Resistant MFA for Privileged Roles

Same structure as `privileged-roles-mfa`, but checks for the built-in "Phishing-resistant MFA" authentication strength (FIDO2, Windows Hello, certificate-based auth) instead of standard MFA. Standard MFA methods like SMS or phone calls can be intercepted via SIM-swapping or social engineering; phishing-resistant methods are immune to these attacks. Custom authentication strength policies are not recognized.

| Result | Condition |
|--------|-----------|
| PASS | All 14 roles covered by enforced policies with no exclusions |
| FAIL | No matching policy, only report-only policies, or some roles not covered (lists uncovered roles) |
| WARN | All roles covered but policies have user/group exclusions |

> **Recommendation:** Create or enable CA policies requiring phishing-resistant MFA authentication strength for all privileged roles.

#### `global-admin-count` — Global Administrator Count

Checks whether the Global Administrator role has between 2 and 8 cloud-only user members. Too few Global Admins risks lockout if an account is lost; too many expands the attack surface unnecessarily. On-premises synced accounts are flagged because compromising the on-prem AD would then grant cloud admin access. Group assignments are recursively expanded. Service principals are reported separately but don't count toward the threshold.

| Result | Condition |
|--------|-----------|
| PASS | 2–8 cloud-only users hold Global Administrator |
| FAIL | Fewer than 2 users, more than 8 users, or any on-premises synced user detected |

> **Recommendation:** Ensure 2–8 cloud-only user accounts are assigned to Global Administrator.

#### `privileged-roles-license` — Privileged Role Licensing

Checks whether all users in privileged roles (including nested group members) have an active Entra ID P1 or P2 license plan (`AAD_PREMIUM` or `AAD_PREMIUM_P2` with status `Enabled`). P1/P2 is required for features like PIM and CA policies targeting roles.

| Result | Condition |
|--------|-----------|
| PASS | All resolved users have an active P1 or P2 plan |
| FAIL | One or more users lack P1/P2 (lists them) |
| WARN | No user members found in scope, or some API lookups failed |

> **Recommendation:** Assign Entra ID P1 or P2 licensing to all privileged role members.

<details>
<summary>Privileged roles referenced by these checks</summary>

1. Global Administrator
2. Privileged Role Administrator
3. Privileged Authentication Administrator
4. Partner Tier2 Support
5. Security Administrator
6. SharePoint Administrator
7. Exchange Administrator
8. Conditional Access Administrator
9. Helpdesk Administrator
10. Application Administrator
11. Cloud Application Administrator
12. User Administrator
13. Authentication Administrator
14. Billing Administrator

</details>

### Shadow Admin Detection

#### `shadow-admins-app-owners` — Application Owner Shadow Admins

Checks whether any users own service principals (or their linked app registrations) that hold privileged directory roles or sensitive Graph permissions. Owners can add credentials to the app and act as it, effectively gaining its privileges without a direct role assignment.

| Result | Condition |
|--------|-----------|
| PASS | No user owners found on privileged service principals or app registrations |
| WARN | One or more shadow admins found (lists user, app, and ownership source: service principal, app registration, or both) |

> **Recommendation:** Remove unnecessary owners or replace with dedicated admin accounts.

#### `shadow-admins-group-owners` — Group Owner Shadow Admins

Checks whether any users own role-assignable groups that are assigned privileged directory roles. Group owners can add themselves as members and inherit the group's role assignments.

| Result | Condition |
|--------|-----------|
| PASS | No user owners found on privileged groups |
| WARN | One or more shadow admins found (lists user, group, and role) |

> **Recommendation:** Remove unnecessary owners or use PIM for just-in-time access.

#### `dynamic-group-hijack` — Dynamic Group Membership Hijack

Checks whether dynamic membership groups assigned to privileged roles use mutable user attributes in their membership rules. Attributes like `department`, `jobTitle`, `city`, `companyName`, `usageLocation`, etc. can be modified by users or admins, allowing privilege escalation.

| Result | Condition |
|--------|-----------|
| PASS | No dynamic groups in privileged roles, or all rules use only immutable attributes |
| FAIL | One or more dynamic rules reference mutable attributes (lists group and attributes) |
| WARN | Dynamic privileged groups exist but rules don't reference known mutable attributes |

> **Recommendation:** Replace mutable attributes with immutable ones (e.g. `user.objectId`, `user.extensionAttributes`) or use static groups with access reviews.

### Guest & Authentication

#### `guest-invite-policy` — Guest Invitation Policy

Checks who can invite external guest users to the tenant. Reads the `allowInvitesFrom` setting on the authorization policy. Overly permissive invitation settings allow any user (or even existing guests) to bring external identities into the tenant, increasing the risk of data exposure and lateral movement.

| Result | Condition |
|--------|-----------|
| PASS | Guest invitations are disabled (`none`) |
| FAIL | Everyone, including existing guests, can invite new guests (`everyone`) |
| WARN | Only admins and Guest Inviter role, or admins plus all member users |

> **Recommendation:** Restrict guest invitations to admins only or disable entirely.

#### `guest-access` — Guest User Access Level

Checks what level of directory access guest users have. Reads the `guestUserRoleId` setting. When guests have the same access as members, they can enumerate all users, groups, and applications in the directory — information that can be used for targeted attacks or data exfiltration.

| Result | Condition |
|--------|-----------|
| PASS | Guest access is limited (own profile and limited directory info) or restricted (own directory object only) |
| FAIL | Guest users have the same access as member users |

> **Recommendation:** Restrict guest access to limited or restricted level.

#### `auth-methods-number-matching` — Authenticator Number Matching

Checks whether number matching is enforced in Microsoft Authenticator for all users. Without number matching, users can approve MFA prompts they didn't initiate (MFA fatigue attacks).

| Result | Condition |
|--------|-----------|
| PASS | Number matching enabled for all users, or Microsoft-managed default (on by default) |
| FAIL | Number matching is explicitly disabled |
| WARN | Microsoft Authenticator is disabled entirely, or number matching is only enabled for specific groups (not all users) |

> **Recommendation:** Enable number matching for all users.

## Required Permissions

The service principal needs these MS Graph application permissions:

- `Policy.Read.All`
- `RoleManagement.Read.Directory`
- `Application.Read.All`
- `User.Read.All` - for resolving reviewer display names
- `Group.Read.All` - for resolving reviewer display names and group ownership

## Development

```bash
# Run tests
uv run pytest

# Run with verbose output
uv run pytest -v
```
