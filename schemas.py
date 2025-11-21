"""
Database Schemas for Email Validator App

Each Pydantic model represents a MongoDB collection. The collection name is the lowercase
of the class name.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime

# Users
class Appuser(BaseModel):
    email: str = Field(..., description="Unique login email")
    name: Optional[str] = Field(None, description="Display name")
    password_hash: str = Field(..., description="Hex digest of salted hash")
    password_salt: str = Field(..., description="Random salt used for hashing")
    role: Literal["user", "admin"] = Field("user", description="Access role")
    is_active: bool = Field(True, description="Active flag")

# Sessions (token-based auth)
class Session(BaseModel):
    user_id: str = Field(..., description="Reference to appuser _id")
    token: str = Field(..., description="Bearer token")
    expires_at: Optional[datetime] = Field(None, description="Expiration time")
    revoked: bool = Field(False, description="Revoked flag")

# Email validations
class Emailcheck(BaseModel):
    user_id: str = Field(..., description="Owner user id")
    email: str = Field(..., description="Email to validate")
    status: Literal["valid", "invalid", "unknown"] = Field("unknown", description="Validation status")
    reason: Optional[str] = Field(None, description="Failure reason if any")
    deliverable: Optional[bool] = Field(None, description="Is deliverable based on DNS checks")
    suggestions: Optional[List[str]] = Field(default=None, description="Suggested corrections if any")
    is_disposable: Optional[bool] = Field(None, description="Disposable domain flagged by library")
