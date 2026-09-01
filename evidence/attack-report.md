# Attack comparison

| Profile | Category | Attack success | Reason |
|---|---|---:|---|
| vulnerable | cross_tenant_retrieval | true | ATTACK_SUCCEEDED |
| vulnerable | wrong_audience_side_effect | true | ATTACK_SUCCEEDED |
| hardened | cross_tenant_retrieval | false | TOKEN_AUDIENCE_INVALID |
| hardened | wrong_audience_side_effect | false | TOKEN_AUDIENCE_INVALID |
