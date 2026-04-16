import json

from flask import Blueprint, flash, redirect, render_template, request, url_for

from services.fulfillment import create_split_orders, get_grouped_orders, plan_multi_store_fulfillment

orders_bp = Blueprint("orders", __name__)


def _normalize_review_items(raw_items):
    review_items = []
    total = 0

    for item in raw_items:
        name = (item.get("name") or "").strip()
        quantity = int(item.get("quantity", 1) or 1)
        price = float(item.get("price", 0) or 0)
        if not name or quantity <= 0:
            continue

        subtotal = round(quantity * price, 2)
        total += subtotal
        review_items.append(
            {
                "name": name,
                "quantity": quantity,
                "price": price,
                "subtotal": subtotal,
            }
        )

    return review_items, round(total, 2)


@orders_bp.route("/order_review", methods=["POST"])
def order_review():
    items_json = request.form.get("items_json", "[]")
    preferred_store_slug = (request.form.get("slug") or "").strip()

    try:
        raw_items = json.loads(items_json)
    except json.JSONDecodeError:
        raw_items = []

    item_list, total = _normalize_review_items(raw_items)
    return render_template(
        "your_order.html",
        mode="review",
        store_name=preferred_store_slug or "Marketplace",
        slug=preferred_store_slug,
        items=item_list,
        total=total,
        raw_items=item_list,
    )


@orders_bp.route("/submit_order", methods=["POST"])
def submit_order():
    phone = (request.form.get("phone") or "").strip()
    delivery_type = (request.form.get("delivery_type") or "pickup").strip()
    address = (request.form.get("address") or "").strip()
    preferred_store_slug = (request.form.get("slug") or "").strip() or None

    fake_numbers = {
        "1234567890", "9999999999", "8888888888", "7777777777",
        "6666666666", "5555555555", "4444444444", "3333333333",
        "2222222222", "1111111111", "0000000000",
    }
    if phone in fake_numbers or not phone.isdigit() or len(phone) != 10:
        return "Invalid phone number", 400

    if delivery_type == "delivery" and len(address) < 5:
        return "Invalid address", 400

    try:
        raw_items = json.loads(request.form.get("items_json", "[]"))
    except json.JSONDecodeError:
        return "Invalid items", 400

    fulfillment_plan = plan_multi_store_fulfillment(raw_items, preferred_store_slug=preferred_store_slug)
    if not fulfillment_plan["ok"]:
        review_items, review_total = _normalize_review_items(raw_items)
        return render_template(
            "your_order.html",
            mode="review",
            store_name=preferred_store_slug or "Marketplace",
            slug=preferred_store_slug or "",
            items=review_items,
            total=review_total,
            raw_items=review_items,
            error_message=", ".join(fulfillment_plan["errors"]),
        ), 400

    try:
        group_code, created_orders = create_split_orders(
            fulfillment_plan["assignments"],
            customer_phone=phone,
            delivery_mode=delivery_type,
            customer_address=address,
        )
    except ValueError as exc:
        return str(exc), 409

    summary = get_grouped_orders(group_code=group_code)
    return render_template(
        "your_order.html",
        mode="placed",
        grouped_orders=summary["orders"],
        grand_total=summary["grand_total"],
        message=summary["message"],
        order_group_code=group_code,
        order_ids=[order.id for order in created_orders],
    )


@orders_bp.route("/your_order", methods=["GET"])
def your_order():
    group_code = (request.args.get("group_code") or "").strip()
    phone = (request.args.get("phone") or "").strip()

    summary = get_grouped_orders(group_code=group_code or None, phone=phone or None, latest_only=not group_code)
    if not summary:
        flash("No order found.", "warning")
        return redirect(url_for("marketplace.marketplace"))

    return render_template(
        "your_order.html",
        mode="placed",
        grouped_orders=summary["orders"],
        grand_total=summary["grand_total"],
        message=summary["message"],
        order_group_code=group_code or "",
    )
