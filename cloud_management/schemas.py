from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

# Base schemas for common attributes
class UserBase(BaseModel):
    username: str
    email: str

class PlanBase(BaseModel):
    name: str
    description: str
    api_limit: Optional[int] = None
    permission_ids: List[int] = []
    #permission_id: Optional[int] = None

class PermissionBase(BaseModel):
    name: str
    api_endpoint: str
    description: str

# Schemas for creating new instances
class UserCreate(UserBase):
    is_admin: bool | None = None
    password: str


class User(UserBase):
    id: int
    is_admin: bool
    plan_id: Optional[int] = None

    class Config:
        orm_mode = True

class Plan(PlanBase):
    id: int
    users: List[User] = []

    class Config:
        orm_mode = True

class Permission(PermissionBase):
    id: int

    class Config:
        orm_mode = True

class SubscriptionBase(BaseModel):
    user_id: int
    plan_id: int

class SubscriptionCreate(SubscriptionBase):
    pass

class Subscription(SubscriptionBase):
    id: int
    start_date: datetime
    plan: Plan

    class Config:
        orm_mode = True