import os
import razorpay

client = razorpay.Client(
    auth=(
        os.environ.get("RAZORPAY_KEY_ID"),
        os.environ.get("RAZORPAY_KEY_SECRET")
    )
)
