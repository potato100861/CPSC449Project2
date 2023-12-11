from datetime import datetime, timedelta
from functools import partial
import random
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import models, schemas
from .database import SessionLocal, engine


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if user is None:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_user_db(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password, is_admin = user.is_admin)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try: 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def is_current_user_admin(current_user: Annotated[models.User, Depends(get_current_user)]):
    if not current_user.is_admin:
        raise HTTPException(status_code=400, detail="No Permission")
    return current_user

#def has_permission_to_access(api_endpoint: str, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
#    # Get the user's subscription
#    subscription = db.query(models.Subscription).filter(models.Subscription.user_id == current_user.id).first()
#    if not subscription:
#        raise HTTPException(status_code=403, detail="No active subscription found")
#
#    # Get the permissions associated with the user's plan
#    plan_permissions = db.query(models.Permission).filter(models.Permission.plans.any(id=subscription.plan_id)).all()
#
#    # Check if the requested API is in the permissions
#    if not any(permission.api_endpoint == api_endpoint for permission in plan_permissions):
#        raise HTTPException(status_code=403, detail="Access to the API is not permitted")
#
#    return True


@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="User already registered")
    return create_user_db(db=db, user=user)


@app.put("/users/", response_model=schemas.User)
def update_user(user: schemas.User, db: Session = Depends(get_db),
                current_user: schemas.User = Depends(is_current_user_admin)):
    db_user = db.query(models.User).filter(models.User.id == user.id).first()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update user fields if provided in the request
    if user.username is not None:
        db_user.username = user.username
    if user.email is not None:
        db_user.email = user.email
    if user.is_admin is not None:
        db_user.is_admin = user.is_admin
    # Update other fields as necessary

    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user


#Subscription Plan Management - Create
@app.post("/plans/", response_model=schemas.Plan)
def create_plan(plan: schemas.PlanBase, db: Session = Depends(get_db),
                current_user: schemas.User = Depends(is_current_user_admin)):
    db_plan = models.Plan(name=plan.name, description=plan.description, api_limit=plan.api_limit)
    db.add(db_plan)
    db.commit()
    db.refresh(db_plan)
    return db_plan


#Subscription Plan Management - Update
@app.put("/plans/{plan_id}", response_model=schemas.Plan)
def update_plan(plan_id: int, plan: schemas.PlanBase, db: Session = Depends(get_db),
                current_user: schemas.User = Depends(is_current_user_admin)):
    # Fetch the existing plan
    db_plan = db.query(models.Plan).filter(models.Plan.id == plan_id).first()
    if not db_plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    # Update plan fields if provided in the request
    if plan.name is not None:
        db_plan.name = plan.name
    if plan.description is not None:
        db_plan.description = plan.description
    if plan.api_limit is not None:
        db_plan.api_limit = plan.api_limit

    db.commit()
    db.refresh(db_plan)
    return db_plan


#Subscription Plan Management - Update
@app.delete("/plans/{plan_id}", status_code=204)
def delete_plan(plan_id: int, db: Session = Depends(get_db),
                current_user: schemas.User = Depends(is_current_user_admin)):
    # Fetch the plan to delete
    db_plan = db.query(models.Plan).filter(models.Plan.id == plan_id).first()
    if not db_plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    # Delete the plan
    db.delete(db_plan)
    db.commit()
    return {"detail": "Plan successfully deleted"}


#Permission Management - create
@app.post("/permissions", response_model=schemas.PermissionBase)
def create_permission(permission: schemas.PermissionBase, 
                      db: Session = Depends(get_db),
                      current_user: schemas.User = Depends(is_current_user_admin)):
    
    db_permission = models.Permission(**permission.model_dump())
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission


#Permission Management - update
@app.put("/permissions/{permission_id}", response_model=schemas.PermissionBase)
def update_permission(permission_id: int, 
                      permission: schemas.PermissionBase, 
                      db: Session = Depends(get_db),
                      current_user: schemas.User = Depends(is_current_user_admin)):

    # Fetch the existing permission
    db_permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if not db_permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Update permission fields if provided in the request
    if permission.name is not None:
        db_permission.name = permission.name
    if permission.api_endpoint is not None:
        db_permission.api_endpoint = permission.api_endpoint
    if permission.description is not None:
        db_permission.description = permission.description

    db.commit()
    db.refresh(db_permission)
    return db_permission


#Permission Management - delete
@app.delete("/permissions/{permission_id}", status_code=204)
def delete_permission(permission_id: int, 
                      db: Session = Depends(get_db),
                      current_user: schemas.User = Depends(is_current_user_admin)):
    # Fetch the permission to delete
    db_permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if not db_permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Delete the permission
    db.delete(db_permission)
    db.commit()
    return {"detail": "Permission successfully deleted"}

@app.post("/subscriptions/", response_model=schemas.Subscription)
def subscribe_to_plan(subscription_data: schemas.SubscriptionCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    # Check for existing subscription
    existing_subscription = db.query(models.Subscription).filter(models.Subscription.user_id == current_user.id).first()
    if existing_subscription:
        raise HTTPException(status_code=400, detail="User already has an active subscription. Update or delete the current plan before subscribing to a new one.")

    # Create a new subscription
    new_subscription = models.Subscription(user_id=subscription_data.user_id, plan_id=subscription_data.plan_id)
    db.add(new_subscription)
    db.commit()
    db.refresh(new_subscription)
    return new_subscription


@app.get("/subscriptions/{user_id}", response_model=schemas.Subscription)
def get_subscription_details(user_id: int, db: Session = Depends(get_db)):
    subscription = db.query(models.Subscription).filter(models.Subscription.user_id == user_id).first()
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return subscription


@app.put("/subscriptions/{user_id}", response_model=schemas.Subscription)
def modify_user_plan(user_id: int, subscription_data: schemas.SubscriptionCreate, 
                     db: Session = Depends(get_db), 
                     current_user: schemas.User = Depends(is_current_user_admin)):
    subscription = db.query(models.Subscription).filter(models.Subscription.user_id == user_id).first()
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    subscription.plan_id = subscription_data.plan_id
    db.commit()
    db.refresh(subscription)
    return subscription





@app.get("/access/{user_id}/{api_request}")
def check_access_permission(user_id: int, api_request: str, db: Session = Depends(get_db)
):
    # Fetch the user and their subscription
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.plan:
        raise HTTPException(status_code=404, detail="User or subscription not found")

    # Check permissions
    plan_permissions = db.query(models.Permission).join(models.Plan.permissions).filter(models.Plan.id == user.plan_id).all()
    if api_request not in [permission.api_endpoint for permission in plan_permissions]:
        raise HTTPException(status_code=403, detail="Access to the requested API is not permitted")

    return {"message": "Access granted"}


#6 random APIs similar to Cloud Services which will be used 
# as the services that are being managed by this system

@app.get("/api/time")
def get_current_time(db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    return {"current_time": datetime.now().isoformat()}

@app.post("/api/echo")
def echo_message(message: str):
    return {"message": message}

@app.get("/api/sum")
def calculate_sum(a: int, b: int):
    return {"sum": a + b}

@app.get("/api/random")
def generate_random_number(min: int = 0, max: int = 100):
    return {"random_number": random.randint(min, max)}

@app.get("/api/convert_temp")
def convert_temperature(celsius: float):
    fahrenheit = (celsius * 9/5) + 32
    return {"fahrenheit": fahrenheit}

@app.get("/api/palindrome")
def check_palindrome(text: str):
    return {"is_palindrome": text == text[::-1]}


