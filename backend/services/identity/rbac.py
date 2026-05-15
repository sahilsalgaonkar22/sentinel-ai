
from fastapi import Depends, HTTPException
from backend.gateway.middleware.auth import get_current_user
from backend.services.identity.models import UserRole

class RBAC:
    def __init__(self, required_roles: list[str]):
        self.required_roles = required_roles

    def __call__(self, user: dict = Depends(get_current_user)):
        if user["role"] not in self.required_roles:
            raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")
        return user

def admin_only(user: dict = Depends(RBAC([UserRole.ADMIN.value]))):
    return user

def analyst_only(user: dict = Depends(RBAC([UserRole.ADMIN.value, UserRole.ANALYST.value]))):
    return user
