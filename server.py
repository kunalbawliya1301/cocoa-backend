import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from starlette.middleware.cors import CORSMiddleware

from routes import payments

# --------------------------------------------------
# ENV
# --------------------------------------------------
load_dotenv()

# --------------------------------------------------
# APP & ROUTER
# --------------------------------------------------
app = FastAPI()
api_router = APIRouter(prefix="/api", tags=["API"])

# --------------------------------------------------
# DATABASE
# --------------------------------------------------
client = AsyncIOMotorClient(
    os.environ.get("MONGO_URL"),
    tls=True,
    tlsAllowInvalidCertificates=True
)
db = client[os.environ.get("DB_NAME")]

# --------------------------------------------------
# SECURITY
# --------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET", "change-this")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7

# --------------------------------------------------
# MODELS
# --------------------------------------------------
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
    updated_at: Optional[datetime] = None

class MenuItemCreate(BaseModel):
    name: str
    description: str
    price: float
    category: str
    image_url: str
    ingredients: List[str]
    calories: int
    available: bool = True

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

# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(pw, hashed):
    return pwd_context.verify(pw, hashed)

def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security)
):
    payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
    if not user:
        raise HTTPException(401, "User not found")
    return User(**user)

async def get_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user

# --------------------------------------------------
# AUTH
# --------------------------------------------------
@api_router.post("/auth/signup")
async def signup(data: UserCreate):
    if await db.users.find_one({"email": data.email}):
        raise HTTPException(400, "Email exists")

    user = User(email=data.email, name=data.name)
    doc = user.model_dump()
    doc["password"] = hash_password(data.password)
    doc["created_at"] = user.created_at.isoformat()

    await db.users.insert_one(doc)
    token = create_token({"sub": user.id, "role": user.role})
    return {"token": token, "user": user}

@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email}, {"_id": 0})
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_token({"sub": user["id"], "role": user["role"]})
    return {"token": token}

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# --------------------------------------------------
# MENU
# --------------------------------------------------
@api_router.get("/menu/items", response_model=List[MenuItem])
async def get_menu(category: Optional[str] = None):
    q = {"available": True}
    if category:
        q["category"] = category
    return await db.menu_items.find(q, {"_id": 0}).to_list(1000)

@api_router.post("/menu/items", response_model=MenuItem)
async def create_menu(item: MenuItemCreate, admin: User = Depends(get_admin)):
    menu = MenuItem(**item.model_dump())
    await db.menu_items.insert_one(menu.model_dump())
    return menu

@api_router.put("/menu/items/{item_id}", response_model=MenuItem)
async def update_menu_item(item_id: str, item: MenuItemCreate, admin: User = Depends(get_admin)):
    existing = await db.menu_items.find_one({"id": item_id})
    if not existing:
        raise HTTPException(404, "Menu item not found")

    updated = {
        **item.model_dump(),
        "id": item_id,
        "created_at": existing.get("created_at"),
        "updated_at": datetime.now(timezone.utc)
    }

    await db.menu_items.update_one({"id": item_id}, {"$set": updated})
    return MenuItem(**updated)

@api_router.delete("/menu/items/{item_id}")
async def delete_menu_item(item_id: str, admin: User = Depends(get_admin)):
    result = await db.menu_items.delete_one({"id": item_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Menu item not found")
    return {"message": "Menu item deleted successfully"}

@api_router.get("/menu/categories")
async def categories():
    return {"categories": await db.menu_items.distinct("category")}

# --------------------------------------------------
# ORDERS
# --------------------------------------------------
@api_router.post("/orders", response_model=Order)
async def create_order(data: OrderCreate, user: User = Depends(get_current_user)):
    order = Order(
        user_id=user.id,
        user_name=user.name,
        user_email=user.email,
        items=data.items,
        total_amount=data.total_amount
    )
    await db.orders.insert_one(order.model_dump())
    return order

@api_router.get("/orders/my", response_model=List[Order])
async def my_orders(user: User = Depends(get_current_user)):
    return await db.orders.find({"user_id": user.id}, {"_id": 0}).to_list(100)

@api_router.get("/admin/orders", response_model=List[Order])
async def all_orders(admin: User = Depends(get_admin)):
    return await db.orders.find({}, {"_id": 0}).to_list(1000)

# ✅ GET SINGLE ORDER (USER + ADMIN)
@api_router.get("/orders/{order_id}", response_model=Order)
async def get_order_by_id(order_id: str, user: User = Depends(get_current_user)):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(404, "Order not found")

    if user.role != "admin" and order["user_id"] != user.id:
        raise HTTPException(403, "Not allowed")

    return order

# ✅ UPDATE ORDER STATUS (ADMIN)
@api_router.put("/admin/orders/{order_id}/status")
async def update_order_status(
    order_id: str,
    data: OrderStatusUpdate,
    admin: User = Depends(get_admin)
):
    result = await db.orders.update_one(
        {"id": order_id},
        {
            "$set": {
                "status": data.status,
                "updated_at": datetime.now(timezone.utc)
            }
        }
    )

    if result.matched_count == 0:
        raise HTTPException(404, "Order not found")

    return {"message": "Order status updated"}

# --------------------------------------------------
# TESTIMONIALS
# --------------------------------------------------
@api_router.get("/testimonials", response_model=List[Testimonial])
async def testimonials():
    return await db.testimonials.find({}, {"_id": 0}).to_list(100)

# --------------------------------------------------
# REGISTER ROUTERS
# --------------------------------------------------
app.include_router(api_router)
app.include_router(payments.router)

# --------------------------------------------------
# MIDDLEWARE
# --------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------
# SHUTDOWN
# --------------------------------------------------
@app.on_event("shutdown")
async def shutdown():
    client.close()
