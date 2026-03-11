import os
import uuid
import hmac
import hashlib

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from lib.razorpay_client import client

router = APIRouter(prefix="/api/payments", tags=["Payments"])


class PaymentOrderItem(BaseModel):
    menu_item_id: str
    quantity: int = Field(gt=0)


class CreateOrderPayload(BaseModel):
    items: list[PaymentOrderItem]


@router.post("/create-order")
async def create_razorpay_order(payload: CreateOrderPayload, request: Request):
    if not payload.items:
        raise HTTPException(status_code=400, detail="Cart is empty")

    db = getattr(request.app.state, "db", None)
    if db is None:
        raise HTTPException(status_code=500, detail="Database not initialized")
    menu_ids = [item.menu_item_id for item in payload.items]
    menu_docs = await db.menu_items.find(
        {"id": {"$in": menu_ids}, "available": True},
        {"_id": 0, "id": 1, "price": 1},
    ).to_list(1000)
    menu_by_id = {item["id"]: item for item in menu_docs}

    total_amount = 0.0
    for item in payload.items:
        menu_item = menu_by_id.get(item.menu_item_id)
        if not menu_item:
            raise HTTPException(
                status_code=400,
                detail=f"Menu item unavailable: {item.menu_item_id}",
            )
        total_amount += float(menu_item["price"]) * item.quantity

    amount_paise = int(round(total_amount * 100))
    if amount_paise <= 0:
        raise HTTPException(status_code=400, detail="Invalid order amount")

    try:
        order = client.order.create(
            {
                "amount": amount_paise,
                "currency": "INR",
                "receipt": f"receipt_{uuid.uuid4().hex[:12]}",
                "payment_capture": 1,
            }
        )

        return {
            "order_id": order["id"],
            "amount": order["amount"],
            "currency": order["currency"],
        }
    except HTTPException:
        raise
    except Exception as e:
        print("RAZORPAY ERROR:", repr(e))
        raise HTTPException(
            status_code=500,
            detail="Razorpay order creation failed",
        )


class VerifyPaymentPayload(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


@router.post("/verify")
def verify_payment(payload: VerifyPaymentPayload):
    secret = os.environ.get("RAZORPAY_KEY_SECRET")

    if not secret:
        raise HTTPException(
            status_code=500,
            detail="Razorpay secret not configured"
        )

    message = f"{payload.razorpay_order_id}|{payload.razorpay_payment_id}"

    expected_signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    if expected_signature != payload.razorpay_signature:
        raise HTTPException(
            status_code=400,
            detail="Payment verification failed"
        )

    return {
        "status": "verified"
    }
