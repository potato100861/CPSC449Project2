from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, Table
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(256))
    is_admin = Column(Boolean, default=False)
    plan_id = Column(Integer, ForeignKey("plans.id"))
    # subscription_id = Column(Integer, ForeignKey("subscriptions.id"))

    api_usage = relationship("ApiUsage", back_populates="user")
    

plan_permission = Table('plan_permission', Base.metadata,
    Column('plan_id', ForeignKey('plans.id'), primary_key = True),
    Column('permission_id', ForeignKey('permissions.id'), primary_key=True)
)

class Plan(Base):
    __tablename__ = "plans"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), index=True)
    description = Column(String(256))
    api_limit = Column(Integer)
    #permission_id = Column(Integer, ForeignKey("permissions.id"))
    
    subscriptions = relationship("Subscription", back_populates="plan")
    permissions = relationship("Permission", secondary=plan_permission, back_populates="plans")


class Permission(Base):
    __tablename__="permissions"
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    api_endpoint = Column(String(100))
    description = Column(String(256))

    plans = relationship("Plan", secondary=plan_permission, back_populates="permissions")

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    plan_id = Column(Integer, ForeignKey('plans.id'))
    start_date = Column(DateTime, default=datetime.utcnow)
    end_date = Column(DateTime, nullable=True)  # Optional: if you want to track subscription end

    
    plan = relationship("Plan", back_populates="subscriptions")

class ApiUsage(Base):
    __tablename__ = "api_usage"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    api_endpoint = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="api_usage")

# You can add more models as needed based on your application requirements
