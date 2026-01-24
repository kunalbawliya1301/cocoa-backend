from fastapi import APIRouter, Depends, HTTPException
from lib.razorpay_client import client

router = APIRouter(prefix="/api/payments", tags=["Payments"])

@router.post("/create-order")
def create_razorpay_order(data: dict):
    amount = data.get("amount")

    if not amount or amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")

    try:
        order = client.order.create({
            "amount": int(amount * 100),  # rupees → paise
            "currency": "INR",
            "receipt": "receipt_test"
        })
        return order
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Razorpay order creation failed")
