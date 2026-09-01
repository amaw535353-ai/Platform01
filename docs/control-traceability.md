# Control traceability
| Control | Automated test | Evidence/status |
|---|---|---|
| Tenant-filtered cited retrieval/quarantine | `tests/integration/test_vertical_slice.py` | pytest output; implemented/tested in-process |
| JWT claim/audience/scope checks | `tests/unit/test_security_core.py` | pytest output; claim validator tested, signature/JWKS integration pending |
| Approval binding, expiry, replay, DLP outbox | `tests/integration/test_vertical_slice.py` | pytest output; implemented/tested |
| Cross-tenant approval/unapproved tool denial | `tests/integration/test_vertical_slice.py` | pytest output; implemented/tested |
| SSRF syntax/private target rejection | `tests/unit/test_security_core.py` | pytest output; no network called |
| Audit chain tamper evidence | `tests/unit/test_security_core.py` | pytest output; mutable storage accurately described |
| Vulnerable/hardened comparison | `tests/security/test_attacks.py` | `evidence/attack-report.{json,md}` |
| PostgreSQL FORCE RLS | database migration | defined; container/raw-SQL verification pending |
| OPA double PEP | Rego policy and core PEP | defined; live OPA integration pending |

