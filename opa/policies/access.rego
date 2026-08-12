package zerotrust.access

import rego.v1

default allow := false

valid_identity if {
    input.user.sub != ""
    input.user.username != ""
}

compliant_device if {
    input.device.managed == true
    input.device.edr == "healthy"
    input.device.patch_age_days <= 14
}

safe_risk if input.risk_score < 60

authorized_role if {
    some role in input.user.roles
    role in {"developer", "admin"}
}

allowed_method if input.request.method == "GET"

allowed_resource if input.request.path == "/project"

allow if {
    valid_identity
    compliant_device
    safe_risk
    authorized_role
    allowed_method
    allowed_resource
}

reason := "allow" if allow
else := "identity_missing" if not valid_identity
else := "device_noncompliant" if not compliant_device
else := "risk_too_high" if not safe_risk
else := "role_not_authorized" if not authorized_role
else := "method_not_allowed" if not allowed_method
else := "resource_not_allowed" if not allowed_resource
else := "policy_denied"

session_ttl_seconds := 3600 if allow
else := 0

decision := {
    "allow": allow,
    "reason": reason,
    "session_ttl_seconds": session_ttl_seconds,
}
