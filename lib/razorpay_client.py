import os
import razorpay
from dotenv import load_dotenv

load_dotenv()

key_id = (os.environ.get("RAZORPAY_KEY_ID") or "").strip()
key_secret = (os.environ.get("RAZORPAY_KEY_SECRET") or "").strip()

if not key_id or not key_secret:
    raise RuntimeError("RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are required")

client = razorpay.Client(
    auth=(
        key_id,
        key_secret
    )
)
