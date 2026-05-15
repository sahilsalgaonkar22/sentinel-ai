
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

# ─── Auth ────────────────────────────────────────
class UserCreate(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    password: str
    full_name: Optional[str] = None
    role: str = "viewer"
    org_id: Optional[str] = None
    org_name: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    org_id: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str
    full_name: Optional[str] = None
    org_name: Optional[str] = None

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    role: str
    org_id: str
    avatar_url: Optional[str]
    last_login: Optional[datetime]

    class Config:
        from_attributes = True
