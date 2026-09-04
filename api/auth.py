from typing import Optional
from functools import wraps
from fastapi import Header, HTTPException
from .models import Role


def get_user_from_header(authorization: Optional[str] = Header(None)) -> dict:
    """
    Parse user info from Authorization header.
    Format: "Bearer <user_id>:<role>"
    Example: "Bearer user-123:compliance"
    """
    if not authorization:
        return {"user_id": "anonymous", "role": Role.VIEWER}
    
    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        
        token = authorization.replace("Bearer ", "")
        parts = token.split(":")
        
        if len(parts) != 2:
            raise HTTPException(status_code=401, detail="Invalid token format")
        
        user_id, role_str = parts
        role = Role(role_str)
        
        return {"user_id": user_id, "role": role}
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid role")


def require_role(*allowed_roles: Role):
    """Decorator to enforce role-based access control."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, authorization: Optional[str] = Header(None), **kwargs):
            user = get_user_from_header(authorization)
            
            if user["role"] not in allowed_roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Role {user['role']} is not authorized for this action. Required: {[r.value for r in allowed_roles]}"
                )
            
            kwargs["user"] = user
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def log_pii_access(user_id: str, record_id: str, action: str, reason_code: str = "other"):
    """Log PII access for audit and compliance."""
    from .storage import put_audit
    import uuid
    from datetime import datetime, timezone
    
    item = {
        "audit_id": str(uuid.uuid4()),
        "user_id": user_id,
        "action": f"pii_{action}",
        "record_id": record_id,
        "reason_code": reason_code,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    put_audit(item)
