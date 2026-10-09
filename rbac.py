import os
import jwt
from enum import Enum
from typing import List, Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key-change-in-production")
ALGORITHM = "HS256"

security_bearer = HTTPBearer(auto_error=False)

class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    TRADER = "TRADER"
    PRO_TRADER = "PRO_TRADER"

class UserContext:
    def __init__(self, user_id: str, email: Optional[str], roles: List[UserRole]):
        self.user_id = user_id
        self.email = email
        self.roles = roles

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> UserContext:
    if not credentials:
        return UserContext(user_id="anon_guest", email=None, roles=[UserRole.ANONYMOUS])

    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub", "unknown")
        email: str = payload.get("email")
        roles_raw: List[str] = payload.get("roles", [UserRole.TRADER.value])
        
        user_roles = [UserRole(r) for r in roles_raw if r in UserRole.__members__]
        return UserContext(user_id=user_id, email=email, roles=user_roles)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired. Please sign in with Google again."
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials."
        )

class RequireRole:
    def __init__(self, required_roles: List[UserRole]):
        self.required_roles = required_roles

    def __call__(self, current_user: UserContext = Depends(get_current_user)) -> UserContext:
        has_permission = any(role in current_user.roles for role in self.required_roles)
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. This feature requires one of the following permissions: {[r.value for r in self.required_roles]}"
            )
        return current_user
