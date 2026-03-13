import os
import uuid
from contextlib import suppress
from datetime import date, datetime, timezone, timedelta
from typing import List, Optional, Literal

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, WebSocket, WebSocketDisconnect
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from slowapi.errors import RateLimitExceeded
from slowapi.extension import _rate_limit_exceeded_handler
from starlette.middleware.cors import CORSMiddleware

from lib.rate_limiter import limiter

# --------------------------------------------------
# ENV
# --------------------------------------------------
load_dotenv()

MONGO_URL = os.environ.get("MONGO_URL", "").strip()
DB_NAME = os.environ.get("DB_NAME", "").strip()
JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", "720"))
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "").strip()
ADMIN_NAME = os.environ.get("ADMIN_NAME", "Cafe Admin").strip()

if not MONGO_URL:
    raise RuntimeError("MONGO_URL is required")
if not DB_NAME:
    raise RuntimeError("DB_NAME is required")
if not JWT_SECRET or JWT_SECRET == "change-this":
    raise RuntimeError("JWT_SECRET must be configured and must not be a placeholder")

# --------------------------------------------------
# APP & ROUTER
# --------------------------------------------------
app = FastAPI()
api_router = APIRouter(prefix="/api", tags=["API"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --------------------------------------------------
# DATABASE
# --------------------------------------------------
client = AsyncIOMotorClient(
    MONGO_URL,
    tls=True,
)
db = client[DB_NAME]
app.state.db = db

# --------------------------------------------------
# SECURITY
# --------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
AUTH_COOKIE_NAME = "access_token"

# --------------------------------------------------
# WEBSOCKET CONNECTIONS
# --------------------------------------------------
class ConnectionManager:
    def __init__(self):
        # Maps user_id -> List of active WebSocket connections
        self.active_connections: dict[str, List[WebSocket]] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        if websocket not in self.active_connections[user_id]:
            self.active_connections[user_id].append(websocket)
        print(f"WS connected user={user_id} total={len(self.active_connections[user_id])}")

    def disconnect(self, user_id: str, websocket: WebSocket):
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if len(self.active_connections[user_id]) == 0:
                del self.active_connections[user_id]
            print(f"WS disconnected user={user_id}")

    async def send_personal_message(self, message: dict, user_id: str):
        connections = self.active_connections.get(user_id, [])
        if not connections:
            print(f"No active WS connection for user={user_id}; message={message.get('type')}")
            return

        stale_connections = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"Failed to send to {user_id}: {e}")
                stale_connections.append(connection)

        for connection in stale_connections:
            self.disconnect(user_id, connection)

manager = ConnectionManager()

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
    tags: List[str] = []
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
    tags: List[str] = []


class MenuAvailabilityUpdate(BaseModel):
    available: bool

class OrderItem(BaseModel):
    menu_item_id: str
    name: str
    price: float
    quantity: int

class OrderItemCreate(BaseModel):
    menu_item_id: str
    quantity: int = Field(gt=0)

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    user_email: str
    items: List[OrderItem]
    total_amount: float
    payment_status: str = "paid"
    status: str = "pending"
    table_number: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderCreate(BaseModel):
    items: List[OrderItemCreate]
    table_number: Optional[str] = None

class OrderStatusUpdate(BaseModel):
    status: Literal["pending", "preparing", "ready", "completed"]

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

def set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=JWT_EXPIRATION_HOURS * 60 * 60,
        path="/",
    )

def clear_auth_cookie(response: Response):
    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
    )

def _to_datetime(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)

def normalize_order_doc(doc: dict) -> dict:
    created = doc.get("created_at", doc.get("createdAt"))
    updated = doc.get("updated_at", doc.get("updatedAt", created))
    normalized = {
        "id": doc.get("id", str(uuid.uuid4())),
        "user_id": doc.get("user_id", ""),
        "user_name": doc.get("user_name", "Unknown User"),
        "user_email": doc.get("user_email", ""),
        "items": doc.get("items", []),
        "total_amount": float(doc.get("total_amount", 0)),
        "payment_status": doc.get("payment_status", "paid"),
        "status": doc.get("status", "pending"),
        "table_number": doc.get("table_number", None),
        "created_at": _to_datetime(created),
        "updated_at": _to_datetime(updated),
    }
    return normalized


def build_order_date_query(start_date: Optional[date] = None, end_date: Optional[date] = None) -> dict:
    if not start_date and not end_date:
        return {}

    created_at_filter = {}
    if start_date:
        created_at_filter["$gte"] = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)
    if end_date:
        created_at_filter["$lte"] = datetime.combine(end_date, datetime.max.time(), tzinfo=timezone.utc)
    return {"created_at": created_at_filter}


class AdminAnalytics(BaseModel):
    today_revenue: float
    week_revenue: float
    month_revenue: float
    total_orders: int
    total_revenue: float

async def get_current_user(request: Request):
    token = request.cookies.get(AUTH_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()

    if not token:
        raise HTTPException(401, "Not authenticated")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid token payload")

    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(401, "User not found")
    return User(**user)

async def get_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


async def get_user_from_token(token: str) -> User:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid token payload")

    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(401, "User not found")
    return User(**user)


async def notify_admins_new_order(order: Order):
    admin_users = await db.users.find({"role": "admin"}, {"_id": 0, "id": 1}).to_list(100)
    if not admin_users:
        return

    message = {
        "type": "new_order",
        "order": {
            "id": order.id,
            "user_name": order.user_name,
            "total_amount": order.total_amount,
            "table_number": order.table_number,
            "status": order.status,
            "created_at": order.created_at.isoformat(),
            "items": [item.model_dump() for item in order.items],
        },
    }
    for admin in admin_users:
        await manager.send_personal_message(message, admin["id"])

# --------------------------------------------------
# AUTH
# --------------------------------------------------
@api_router.post("/auth/signup")
@limiter.limit("3/minute")
async def signup(request: Request, data: UserCreate, response: Response):
    if await db.users.find_one({"email": data.email}):
        raise HTTPException(400, "Email exists")

    user = User(email=data.email, name=data.name)
    doc = user.model_dump()
    doc["password"] = hash_password(data.password)
    doc["created_at"] = user.created_at.isoformat()

    await db.users.insert_one(doc)
    token = create_token({"sub": user.id, "role": user.role})
    set_auth_cookie(response, token)
    return {"token": token, "user": user}

@api_router.post("/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, data: UserLogin, response: Response):
    user = await db.users.find_one({"email": data.email}, {"_id": 0})
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_token({"sub": user["id"], "role": user["role"]})
    set_auth_cookie(response, token)
    return {"token": token}

@api_router.post("/auth/logout")
async def logout(response: Response):
    clear_auth_cookie(response)
    return {"message": "Logged out"}

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@api_router.get("/health")
async def health_check():
    return {"status": "ok"}

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


@api_router.patch("/admin/menu/{item_id}/availability", response_model=MenuItem)
async def update_menu_item_availability(
    item_id: str,
    data: MenuAvailabilityUpdate,
    admin: User = Depends(get_admin),
):
    existing = await db.menu_items.find_one({"id": item_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Menu item not found")

    updated = {
        **existing,
        "available": data.available,
        "updated_at": datetime.now(timezone.utc),
    }
    await db.menu_items.update_one(
        {"id": item_id},
        {"$set": {"available": data.available, "updated_at": updated["updated_at"]}},
    )
    return MenuItem(**updated)

@api_router.get("/menu/categories")
async def categories():
    return {"categories": await db.menu_items.distinct("category")}

# --------------------------------------------------
# ORDERS
# --------------------------------------------------
@api_router.post("/orders", response_model=Order)
async def create_order(data: OrderCreate, user: User = Depends(get_current_user)):
    if not data.items:
        raise HTTPException(400, "Order must include at least one item")

    menu_ids = [item.menu_item_id for item in data.items]
    menu_docs = await db.menu_items.find(
        {"id": {"$in": menu_ids}, "available": True},
        {"_id": 0, "id": 1, "name": 1, "price": 1},
    ).to_list(1000)
    menu_by_id = {item["id"]: item for item in menu_docs}

    normalized_items: List[OrderItem] = []
    computed_total = 0.0
    for item in data.items:
        if item.quantity <= 0:
            raise HTTPException(400, "Item quantity must be greater than 0")

        menu_item = menu_by_id.get(item.menu_item_id)
        if not menu_item:
            raise HTTPException(400, f"Menu item unavailable: {item.menu_item_id}")

        canonical_price = float(menu_item["price"])
        computed_total += canonical_price * item.quantity
        normalized_items.append(
            OrderItem(
                menu_item_id=menu_item["id"],
                name=menu_item["name"],
                price=canonical_price,
                quantity=item.quantity,
            )
        )

    order = Order(
        user_id=user.id,
        user_name=user.name,
        user_email=user.email,
        items=normalized_items,
        total_amount=round(computed_total, 2),
        table_number=data.table_number,
    )
    await db.orders.insert_one(order.model_dump())
    await notify_admins_new_order(order)
    return order

@api_router.get("/orders/my", response_model=List[Order])
async def my_orders(user: User = Depends(get_current_user)):
    orders = await db.orders.find(
        {"user_id": user.id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    return [Order(**normalize_order_doc(order)) for order in orders]

@api_router.get("/orders/{order_id}", response_model=Order)
async def get_order_by_id(
    order_id: str,
    user: User = Depends(get_current_user)
):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})

    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # user can see only their order
    if user.role != "admin" and order["user_id"] != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return Order(**normalize_order_doc(order))


@api_router.get("/admin/orders", response_model=List[Order])
async def all_orders(
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    admin: User = Depends(get_admin),
):
    order_query = build_order_date_query(start_date, end_date)
    orders = await db.orders.find(
        order_query,
        {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    return [Order(**normalize_order_doc(order)) for order in orders]


@api_router.get("/admin/analytics", response_model=AdminAnalytics)
async def admin_analytics(admin: User = Depends(get_admin)):
    now = datetime.now(timezone.utc)
    start_of_today = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)

    pipeline = [
        {
            "$match": {
                "payment_status": "paid",
            }
        },
        {
            "$group": {
                "_id": None,
                "today_revenue": {
                    "$sum": {
                        "$cond": [
                            {"$gte": ["$created_at", start_of_today]},
                            "$total_amount",
                            0,
                        ]
                    }
                },
                "week_revenue": {
                    "$sum": {
                        "$cond": [
                            {"$gte": ["$created_at", seven_days_ago]},
                            "$total_amount",
                            0,
                        ]
                    }
                },
                "month_revenue": {
                    "$sum": {
                        "$cond": [
                            {"$gte": ["$created_at", thirty_days_ago]},
                            "$total_amount",
                            0,
                        ]
                    }
                },
                "total_orders": {"$sum": 1},
                "total_revenue": {"$sum": "$total_amount"},
            }
        },
        {
            "$project": {
                "_id": 0,
                "today_revenue": {"$round": ["$today_revenue", 2]},
                "week_revenue": {"$round": ["$week_revenue", 2]},
                "month_revenue": {"$round": ["$month_revenue", 2]},
                "total_orders": 1,
                "total_revenue": {"$round": ["$total_revenue", 2]},
            }
        },
    ]

    result = await db.orders.aggregate(pipeline).to_list(1)
    if result:
        return AdminAnalytics(**result[0])

    return AdminAnalytics(
        today_revenue=0,
        week_revenue=0,
        month_revenue=0,
        total_orders=0,
        total_revenue=0,
    )

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

    # Fetch the order to get the user_id for notification
    order = await db.orders.find_one({"id": order_id}, {"_id": 0, "user_id": 1, "status": 1})
    if order:
        # Notify the user via WebSocket
        await manager.send_personal_message(
            {"type": "order_status_update", "order_id": order_id, "status": data.status},
            order["user_id"]
        )

    return {"message": "Order status updated"}

# --------------------------------------------------
# TESTIMONIALS
# --------------------------------------------------
@api_router.get("/testimonials", response_model=List[Testimonial])
async def testimonials():
    return await db.testimonials.find({}, {"_id": 0}).to_list(100)

# --------------------------------------------------
# STARTUP
# --------------------------------------------------
@app.on_event("startup")
async def startup():
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        return

    existing = await db.users.find_one({"email": ADMIN_EMAIL}, {"_id": 0, "id": 1})
    if existing:
        return

    admin_user = User(email=ADMIN_EMAIL, name=ADMIN_NAME, role="admin")
    doc = admin_user.model_dump()
    doc["password"] = hash_password(ADMIN_PASSWORD)
    doc["created_at"] = admin_user.created_at.isoformat()
    await db.users.insert_one(doc)
    print(f"Seeded admin user: {ADMIN_EMAIL}")

# --------------------------------------------------
# REGISTER ROUTERS
# --------------------------------------------------
from routes import admin, payments

app.include_router(api_router)
app.include_router(admin.router)
app.include_router(payments.router)


# --------------------------------------------------
# WEBSOCKET ENDPOINTS
# --------------------------------------------------
async def authenticate_websocket_user(websocket: WebSocket, token: Optional[str]) -> User:
    resolved_token = token or websocket.cookies.get(AUTH_COOKIE_NAME)
    if not resolved_token:
        await websocket.close(code=1008)
        raise HTTPException(401, "Not authenticated")

    try:
        return await get_user_from_token(resolved_token)
    except HTTPException:
        await websocket.close(code=1008)
        raise


async def websocket_orders_handler(websocket: WebSocket, token: Optional[str] = None):
    try:
        user = await authenticate_websocket_user(websocket, token)
        user_id = user.id

        await manager.connect(user_id, websocket)
        await websocket.send_json({"type": "ws_connected"})
        
        try:
            while True:
                message = await websocket.receive_text()
                if message == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            manager.disconnect(user_id, websocket)
        finally:
            with suppress(Exception):
                manager.disconnect(user_id, websocket)
    except Exception as e:
        print(f"WebSocket auth failed: {e}")
        with suppress(Exception):
            await websocket.close(code=1008)


@app.websocket("/api/ws/orders")
async def websocket_orders_cookie_endpoint(websocket: WebSocket):
    await websocket_orders_handler(websocket)


@app.websocket("/api/ws/orders/{token}")
async def websocket_orders_token_endpoint(websocket: WebSocket, token: str):
    await websocket_orders_handler(websocket, token)

# --------------------------------------------------
# MIDDLEWARE
# --------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
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
