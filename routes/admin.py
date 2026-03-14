import csv
import io
from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, Response

from server import Order, build_order_date_query, db, get_admin, normalize_order_doc


router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/orders/export")
async def export_orders_csv(
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    admin=Depends(get_admin),
):
    order_query = build_order_date_query(start_date, end_date)
    orders = await db.orders.find(order_query, {"_id": 0}).sort("created_at", -1).to_list(5000)
    normalized_orders = [Order(**normalize_order_doc(order)) for order in orders]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "order_id",
            "customer_name",
            "items",
            "total_amount",
            "payment_method",
            "payment_status",
            "created_at",
            "table_number",
        ]
    )

    for order in normalized_orders:
        items_summary = ", ".join(f"{item.quantity}x {item.name}" for item in order.items)
        writer.writerow(
            [
                order.id,
                order.user_name,
                items_summary,
                f"{order.total_amount:.2f}",
                order.payment_method,
                order.payment_status,
                order.created_at.isoformat(),
                order.table_number or "",
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="orders.csv"'},
    )
