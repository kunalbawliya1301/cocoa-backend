from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from lib.razorpay_client import client

router = APIRouter(prefix="/api/payments", tags=["Payments"])

USD_TO_INR = 83  # approximate conversion rate

class CreateOrderPayload(BaseModel):
    amount: float  # amount in USD from frontend


@router.post("/create-order")
def create_razorpay_order(payload: CreateOrderPayload):
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")

    try:
        # Convert USD → INR
        amount_in_inr = payload.amount * USD_TO_INR

        order = client.order.create({
            "amount": int(amount_in_inr * 100),  # INR → paise
            "currency": "INR",
            "receipt": "receipt_cocoa",
            "payment_capture": 1
        })

        return {
            "order_id": order["id"],
            "amount": order["amount"],
            "currency": order["currency"]
        }

    except Exception as e:
        print("🔥 RAZORPAY ERROR:", repr(e))
        raise HTTPException(
        status_code=500,
        detail=str(e)
    )

