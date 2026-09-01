package agent.authz
import rego.v1
default decision := {"allow": false, "reason": "POLICY_DEFAULT_DENY", "obligations": {"deny_egress": true}}
decision := {"allow": true, "reason": "POLICY_ALLOW", "obligations": obligations} if {
  input.principal.tenant == input.resource.tenant
  input.tool.required_scope in input.principal.scopes
  not "*" in input.principal.scopes
  obligations := {"require_approval": input.tool.approval, "max_records": 5, "redact": true, "deny_egress": true}
}

