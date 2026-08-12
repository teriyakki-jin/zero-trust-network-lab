package zerotrust.access_test

import data.zerotrust.access
import rego.v1

base_input := {
    "user": {
        "sub": "user-1",
        "username": "alice",
        "roles": ["employee", "developer"],
    },
    "device": {
        "managed": true,
        "edr": "healthy",
        "patch_age_days": 3,
    },
    "risk_score": 10,
    "request": {"method": "GET", "path": "/project"},
}

test_developer_on_compliant_device_is_allowed if {
    access.allow with input as base_input
}

test_unmanaged_device_is_denied if {
    not access.allow with input as object.union(base_input, {
        "device": {"managed": false, "edr": "healthy", "patch_age_days": 3},
    })
}

test_employee_without_developer_role_is_denied if {
    not access.allow with input as object.union(base_input, {
        "user": {"sub": "user-2", "username": "bob", "roles": ["employee"]},
    })
}

test_high_risk_is_denied if {
    not access.allow with input as object.union(base_input, {"risk_score": 80})
}

test_post_is_denied if {
    not access.allow with input as object.union(base_input, {
        "request": {"method": "POST", "path": "/"},
    })
}

test_unknown_resource_is_denied if {
    not access.allow with input as object.union(base_input, {
        "request": {"method": "GET", "path": "/admin"},
    })
}
