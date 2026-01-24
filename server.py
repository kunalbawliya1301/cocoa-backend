import os
import logging
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

import jwt
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    APIRouter,
    HTTPException,
    Depends,
    status
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from starlette.middleware.cors import CORSMiddleware

from routes import payments

# ------------------------------------------------------------------
# ENV
# ------------------------------------------------------------------
load_dotenv()

ROOT_DIR = Path(__file__).parent

# ------------------------------------------------------------------
# APP & ROUTERS (ORDER MATTERS)
# ------------------------------------------------------------------
app = FastAPI()
api_router = APIRouter()

# ------------------------------------------------------------------
# DATABASE
# ------------------------------------------------------------------
mongo_url = os.environ.get("MONGO_URL", "")
client = AsyncIOMotorClient(
    mongo_url,
    tls=True,
    tlsAllowInvalidCertificates=True
)
db = client[os.environ.get("DB_NAME")]

# ------------------------------------------------------------------
# SECURITY
# ------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET", "cocoa-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7

# ------------------------------------------------------------------
# MODELS
# ------------------------------------------------------------------
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    role: str = "customer"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class MenuItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    price: float
    category: str
    image_url: str
    ingredients: List[str]
    calories: int
    available: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MenuItemCreate(BaseModel):
    name: str
    description: str
    price: float
    category: str
    image_url: str
    ingredients: List[str]
    calories: int
    available: bool = True

class MenuItemUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    image_url: Optional[str] = None
    ingredients: Optional[List[str]] = None
    calories: Optional[int] = None
    available: Optional[bool] = None

class OrderItem(BaseModel):
    menu_item_id: str
    name: str
    price: float
    quantity: int

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    user_email: str
    items: List[OrderItem]
    total_amount: float
    status: str = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderCreate(BaseModel):
    items: List[OrderItem]
    total_amount: float

class OrderStatusUpdate(BaseModel):
    status: str

class Testimonial(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    rating: int
    comment: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")

        user = await db.users.find_one({"id": user_id}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return User(**user)

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ------------------------------------------------------------------
# AUTH ROUTES
# ------------------------------------------------------------------
@api_router.post("/auth/signup")
async def signup(data: UserCreate):
    if await db.users.find_one({"email": data.email}):
        raise HTTPException(400, "Email already registered")

    user = User(email=data.email, name=data.name)
    user_dict = user.model_dump()
    user_dict["password"] = hash_password(data.password)
    user_dict["created_at"] = user.created_at.isoformat()

    await db.users.insert_one(user_dict)

    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    return {"token": token, "user": user}

@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email}, {"_id": 0})
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_access_token({"sub": user["id"], "email": user["email"], "role": user["role"]})
    return {"token": token}

# ------------------------------------------------------------------
# REGISTER ROUTERS (VERY IMPORTANT)
# ------------------------------------------------------------------
app.include_router(api_router)
app.include_router(payments.router)

# ------------------------------------------------------------------
# MIDDLEWARE
# ------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# LOGGING & SHUTDOWN
# ------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown():
    client.close()
