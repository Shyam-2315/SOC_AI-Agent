from app.core.security import UserRole


ROLE_PERMISSIONS = {
    UserRole.admin.value: {
        "alerts:read",
        "logs:read",
        "incidents:read",
        "incidents:write",
        "organizations:read",
        "organizations:write",
        "soar:read",
        "threat_hunting:read",
        "copilot:query",
        "users:read",
        "users:write",
    },
    UserRole.analyst.value: {
        "alerts:read",
        "logs:read",
        "incidents:read",
        "incidents:write",
        "organizations:read",
        "soar:read",
        "threat_hunting:read",
        "copilot:query",
    },
    UserRole.viewer.value: {
        "alerts:read",
        "logs:read",
        "incidents:read",
        "organizations:read",
        "soar:read",
        "threat_hunting:read",
    },
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())
