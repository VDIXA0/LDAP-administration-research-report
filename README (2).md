# LDAP Lab: OpenLDAP Implementation

A supervised, isolated laboratory project that builds and evaluates a secured
**OpenLDAP** directory on a single Ubuntu Server VM. It accompanies the research report
*"LDAP: Architecture, Security, and Practical Implementation"*.

> **Scope:** defensive and educational only. Run everything on an isolated
> host-only/NAT lab network with non-sensitive sample data. Never expose ports 389/636
> to a production or public network.

| | |
|---|---|
| **Student** | [Student Name] / [Student ID] |
| **University / Course** | [University Name] / [Course Name / Code] |
| **Instructor** | [Instructor Name] |
| **Submission date** | [Submission Date] |

---

## 1. What is LDAP?

LDAP (Lightweight Directory Access Protocol) is an IETF-standardized (RFC 4510-4519,
LDAPv3) application-layer protocol for accessing and maintaining directory information.
It is a **protocol and data model**, not a product. OpenLDAP (`slapd`) and Microsoft
Active Directory are *implementations* that speak it.

Key concepts: Directory Information Tree (DIT), entry, attribute, object class, schema,
Distinguished Name (DN), Base DN, Organizational Unit (OU).

Core operations: `bind`, `search`, `add`, `delete`, `modify`, `modify DN`, `compare`, `unbind`.

| Method | Port | Encryption |
|---|---|---|
| LDAP | 389/tcp | None by default |
| StartTLS | 389/tcp | In-band upgrade to TLS before credentials are sent |
| LDAPS | 636/tcp | Implicit TLS on connect |

## 2. Lab architecture

```
Client machine (ldapsearch / Apache Directory Studio)
        |
LDAP server VM (Ubuntu Server LTS, slapd)
        |
OpenLDAP (schema + ACLs + TLS)  ->  Directory (DIT, MDB backend)
        |
Isolated lab network (host-only / NAT), no route to production or internet
```

Directory layout used in the lab:

```
dc=example,dc=com
+-- ou=People
|   +-- uid=alice
|   +-- uid=bob
+-- ou=Groups
    +-- cn=students
    +-- cn=administrators
```

## 3. Requirements

| Area | Requirement |
|---|---|
| Hardware | 1-2 vCPU, 1-2 GB RAM, 10-20 GB disk |
| OS | Ubuntu Server LTS (any current Linux with OpenLDAP packages works) |
| Software | `slapd`, `ldap-utils`, `openssl`; optional GUI client |
| Network | Isolated host-only or NAT segment |
| Skills | Basic Linux admin, LDIF syntax |
| Time | About 15-25 hours for a first-time implementer |

## 4. Implementation plan

All commands for every phase are in [`commands.sh`](./commands.sh). It is meant to be
followed **section by section**, not run blindly: some steps are interactive
(`dpkg-reconfigure`, password prompts) and some values must be edited first.

| Phase | Objective | Validation |
|---|---|---|
| 1 | Environment preparation (isolated VM and network) | Connectivity works inside the lab only |
| 2 | Install `slapd` and `ldap-utils` | `systemctl status slapd` active; local `ldapsearch` works |
| 3 | Design the DIT (base DN, People/Groups OUs) | Design reviewed |
| 4 | Verify/load schemas (core, cosine, inetorgperson, nis) | `slapd` starts cleanly |
| 5 | Create OUs, users and groups from LDIF | `ldapsearch` returns expected entries |
| 6 | Configure password hashes; verify simple bind | `ldapwhoami` succeeds/fails as expected |
| 7 | Least-privilege ACLs (`olcAccess`) | Low-privilege out-of-scope actions denied |
| 8 | TLS: lab CA, server certificate, StartTLS, reject plaintext binds | `ldapsearch -ZZ` works; plaintext rejected |
| 9 | Run the test plan | Completed test log |
| 10 | Document configuration and lessons learned | Reproducible by a reviewer |

## 5. Quick start

```bash
# 1. Read and edit the variables at the top of commands.sh
#    (LAB_IP, BASE_DN, ADMIN_PW placeholders)
# 2. Work through commands.sh one phase at a time
less commands.sh
```

## 6. Test plan

| ID | Test | Expected result |
|---|---|---|
| T01 | Server availability | `slapd` active and reachable on the lab network |
| T02 | Valid authentication | `ldapwhoami` returns the correct bind DN |
| T03 | Invalid authentication | Wrong password rejected |
| T04 | Directory search | Filter returns the expected entries |
| T05 | Authorized access | Permitted user reads/modifies allowed attributes |
| T06 | Unauthorized access | Low-privilege bind denied an out-of-scope write |
| T07 | ACL enforcement | Anonymous search of the directory denied |
| T08 | TLS connection | StartTLS negotiation succeeds |
| T09 | Certificate validation | Untrusted certificate rejected when validation is enforced |
| T10 | Logging | Bind/search operations appear in `slapd` logs |
| T11 | Backup / recovery | `slapcat` export and `slapadd` import without data loss |

**Success criteria:** all functional tests (T01-T05, T08, T10, T11) pass and all negative
tests (T06, T07, T09) correctly deny the action. A negative test that unexpectedly
succeeds is a security gap that must be fixed.

Record results in the table in Chapter 15 of the report.

## 7. Security hardening checklist (by priority)

1. Enforce TLS (StartTLS or LDAPS) for all binds
2. Disable anonymous bind and anonymous search
3. Apply least-privilege ACLs
4. Store `userPassword` as salted hashes (`{SSHA}` or stronger)
5. Restrict and monitor `rootDN` use
6. Segment the LDAP server on the network
7. Enable and centralize logging
8. Keep `slapd` and TLS libraries patched
9. Manage certificate expiry and renewal
10. Encrypt and restrict backups

## 8. Demonstration outline

1. `slapd` running and listening on the lab interface only
2. Directory structure shown with `ldapsearch`
3. Users and groups created from LDIF
4. Successful authenticated bind (`ldapwhoami`)
5. Filtered search (e.g. members of a group)
6. Low-privilege bind denied an out-of-scope operation
7. StartTLS session vs. rejected plaintext bind
8. Access logs capturing the above
9. Service restart and reconnection
10. Walkthrough linking each behavior to the RFC/control it demonstrates

## 9. Limitations and future work

Single server, so no replication or high availability (next step: `syncrepl` consumer);
manual backups only; self-signed lab CA; basic logging (next step: forward to a SIEM);
no real application integration (next step: PAM/NSS or a sample web app).

## 10. Feasibility summary

| Category | Score |
|---|---|
| Difficulty | 4/10 |
| Cost | 1/10 |
| Security (achievable) | 7/10 |
| Scalability | 3/10 |
| Learning value | 9/10 |
| University project suitability | 9/10 |
| **Overall feasibility** | **8/10** |

## 11. References

- RFC 4510-4517: LDAPv3 technical specification (IETF)
- OpenLDAP Software 2.6 Administrator's Guide: https://www.openldap.org/doc/admin26/
- IANA Service Name and Port Number Registry
- Microsoft Learn: LDAP signing for AD DS; LDAP authentication with Microsoft Entra Domain Services
- OWASP: LDAP Injection; LDAP Injection Prevention Cheat Sheet; WSTG-INPV-06
