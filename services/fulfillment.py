from collections import defaultdict
from uuid import uuid4

from sqlalchemy import func

from models import Order, OrderItem, Product, StoreSettings, User, db


def _distance_km(customer_lat, customer_lng, store_lat, store_lng):
    if None in (customer_lat, customer_lng, store_lat, store_lng):
        return None
    return ((customer_lat - store_lat) ** 2 + (customer_lng - store_lng) ** 2) ** 0.5


def normalize_requested_items(raw_items):
    aggregated = {}

    for raw_item in raw_items or []:
        name = (raw_item.get("name") or "").strip()
        if not name:
            continue

        quantity = int(raw_item.get("quantity", 1) or 1)
        if quantity <= 0:
            continue

        product_key = name.lower()
        if product_key not in aggregated:
            aggregated[product_key] = {
                "name": name,
                "quantity": 0,
                "product_key": product_key,
            }
        aggregated[product_key]["quantity"] += quantity

    return list(aggregated.values())


def get_marketplace_products(search_query="", category=None):
    query = (
        db.session.query(Product, User, StoreSettings)
        .join(User, Product.seller_id == User.id)
        .outerjoin(StoreSettings, StoreSettings.seller_id == User.id)
        .filter(func.coalesce(StoreSettings.is_open, True).is_(True))
        .filter(Product.is_available.is_(True))
        .filter(Product.quantity > 0)
    )

    if search_query:
        query = query.filter(func.lower(Product.product_name).like(f"%{search_query.lower()}%"))

    if category:
        query = query.filter(func.lower(Product.category) == category.lower())

    rows = query.order_by(Product.product_name.asc(), User.store_name.asc()).all()

    return [
        {
            "product_id": product.id,
            "name": product.product_name,
            "price": product.price,
            "image_url": product.image_url,
            "category": product.category,
            "store_name": store.store_name,
            "store_slug": store.slug,
            "store_status": "Open" if not settings or settings.is_open else "Closed",
        }
        for product, store, settings in rows
    ]


def get_marketplace_categories():
    rows = (
        db.session.query(Product.category)
        .join(User, Product.seller_id == User.id)
        .outerjoin(StoreSettings, StoreSettings.seller_id == User.id)
        .filter(func.coalesce(StoreSettings.is_open, True).is_(True))
        .filter(Product.is_available.is_(True))
        .filter(Product.quantity > 0)
        .filter(Product.category.isnot(None))
        .filter(Product.category != "")
        .distinct()
        .order_by(Product.category.asc())
        .all()
    )
    return [row[0] for row in rows]


def _build_catalog(requested_items, preferred_store_slug=None, customer_lat=None, customer_lng=None):
    product_names = [item["product_key"] for item in requested_items]
    products = (
        db.session.query(Product, User, StoreSettings)
        .join(User, Product.seller_id == User.id)
        .outerjoin(StoreSettings, StoreSettings.seller_id == User.id)
        .filter(func.lower(Product.product_name).in_(product_names))
        .filter(func.coalesce(StoreSettings.is_open, True).is_(True))
        .filter(Product.is_available.is_(True))
        .filter(Product.quantity > 0)
        .all()
    )

    product_catalog = defaultdict(list)
    store_map = {}

    for product, store, settings in products:
        effective_store_id = product.store_id or product.seller_id
        distance = _distance_km(
            customer_lat,
            customer_lng,
            store.latitude if store.latitude is not None else store.store_lat,
            store.longitude if store.longitude is not None else store.store_lng,
        )

        store_map[effective_store_id] = {
            "store_id": effective_store_id,
            "seller_id": store.id,
            "store_name": store.store_name,
            "store_slug": store.slug,
            "distance": distance,
            "is_preferred": store.slug == preferred_store_slug,
        }

        product_catalog[product.product_name.lower()].append(
            {
                "product": product,
                "store_id": effective_store_id,
                "seller_id": store.id,
                "store_name": store.store_name,
                "store_slug": store.slug,
                "available_qty": product.quantity,
                "distance": distance,
            }
        )

    for product_key in product_catalog:
        product_catalog[product_key].sort(
            key=lambda entry: (
                0 if entry["store_slug"] == preferred_store_slug else 1,
                entry["distance"] if entry["distance"] is not None else float("inf"),
                entry["store_name"].lower(),
            )
        )

    return product_catalog, store_map


def plan_multi_store_fulfillment(raw_items, preferred_store_slug=None, customer_lat=None, customer_lng=None):
    requested_items = normalize_requested_items(raw_items)
    if not requested_items:
        return {"ok": False, "message": "No valid items in order.", "errors": ["No valid items in order."]}

    product_catalog, store_map = _build_catalog(
        requested_items,
        preferred_store_slug=preferred_store_slug,
        customer_lat=customer_lat,
        customer_lng=customer_lng,
    )

    errors = []
    remaining_qty = {}
    requested_lookup = {}

    for item in requested_items:
        requested_lookup[item["product_key"]] = item
        total_available = sum(entry["available_qty"] for entry in product_catalog.get(item["product_key"], []))
        if total_available < item["quantity"]:
            errors.append(f"{item['name']} is not available.")
        else:
            remaining_qty[item["product_key"]] = item["quantity"]

    if errors:
        return {"ok": False, "message": "Some items are unavailable.", "errors": errors}

    assignments = defaultdict(list)
    assigned_tracker = set()

    while any(qty > 0 for qty in remaining_qty.values()):
        candidate_scores = []

        for store_id, store_info in store_map.items():
            covered_items = 0
            covered_units = 0

            for product_key, needed_qty in remaining_qty.items():
                if needed_qty <= 0:
                    continue

                store_entry = next(
                    (
                        entry
                        for entry in product_catalog.get(product_key, [])
                        if entry["store_id"] == store_id and entry["available_qty"] > 0
                    ),
                    None,
                )
                if not store_entry:
                    continue

                covered_items += 1
                covered_units += min(needed_qty, store_entry["available_qty"])

            if covered_items:
                candidate_scores.append(
                    (
                        -covered_items,
                        -covered_units,
                        0 if store_info["is_preferred"] else 1,
                        store_info["distance"] if store_info["distance"] is not None else float("inf"),
                        store_info["store_name"].lower(),
                        store_id,
                    )
                )

        if not candidate_scores:
            break

        selected_store_id = sorted(candidate_scores)[0][-1]

        for product_key, needed_qty in list(remaining_qty.items()):
            if needed_qty <= 0:
                continue

            store_entry = next(
                (
                    entry
                    for entry in product_catalog.get(product_key, [])
                    if entry["store_id"] == selected_store_id and entry["available_qty"] > 0
                ),
                None,
            )
            if not store_entry:
                continue

            assign_qty = min(needed_qty, store_entry["available_qty"])
            if assign_qty <= 0:
                continue

            tracker_key = (selected_store_id, store_entry["product"].id)
            if tracker_key in assigned_tracker:
                continue

            assignments[selected_store_id].append(
                {
                    "product": store_entry["product"],
                    "product_name": requested_lookup[product_key]["name"],
                    "quantity": assign_qty,
                    "unit_price": store_entry["product"].price,
                }
            )
            assigned_tracker.add(tracker_key)
            remaining_qty[product_key] -= assign_qty
            store_entry["available_qty"] -= assign_qty

    unresolved = [requested_lookup[key]["name"] for key, qty in remaining_qty.items() if qty > 0]
    if unresolved:
        return {
            "ok": False,
            "message": "Some items could not be assigned.",
            "errors": [f"{name} is not available." for name in unresolved],
        }

    grouped_assignments = []
    for store_id, items in assignments.items():
        store_info = store_map[store_id]
        store_total = sum(item["quantity"] * item["unit_price"] for item in items)
        grouped_assignments.append(
            {
                "store_id": store_id,
                "seller_id": store_info["seller_id"],
                "store_name": store_info["store_name"],
                "store_slug": store_info["store_slug"],
                "distance": store_info["distance"],
                "items": items,
                "total_amount": round(store_total, 2),
            }
        )

    grouped_assignments.sort(
        key=lambda group: (
            0 if group["store_slug"] == preferred_store_slug else 1,
            -(len(group["items"])),
            group["distance"] if group["distance"] is not None else float("inf"),
            group["store_name"].lower(),
        )
    )

    return {
        "ok": True,
        "message": "This order will be fulfilled from multiple nearby stores"
        if len(grouped_assignments) > 1
        else "This order will be fulfilled from a single store",
        "assignments": grouped_assignments,
        "requested_items": requested_items,
    }


def create_split_orders(assignments, customer_phone, delivery_mode, customer_address=""):
    group_code = uuid4().hex
    created_orders = []

    try:
        for assignment in assignments:
            order = Order(
                seller_id=assignment["seller_id"],
                group_code=group_code,
                customer_phone=customer_phone,
                customer_address=customer_address if delivery_mode == "delivery" else "",
                delivery_mode=delivery_mode,
                delivery_charge=0,
                total_amount=assignment["total_amount"],
                status="Pending",
            )
            db.session.add(order)
            db.session.flush()

            for item in assignment["items"]:
                product = Product.query.get(item["product"].id)
                if not product or not product.is_available or product.quantity < item["quantity"]:
                    raise ValueError(f"{item['product_name']} is no longer available.")

                product.quantity -= item["quantity"]
                if product.quantity <= 0:
                    product.quantity = 0
                    product.is_available = False

                db.session.add(
                    OrderItem(
                        order_id=order.id,
                        product_id=product.id,
                        store_id=assignment["seller_id"],
                        product_name=item["product_name"],
                        quantity=item["quantity"],
                        unit_price=item["unit_price"],
                    )
                )

            created_orders.append(order)

        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return group_code, created_orders


def get_grouped_orders(group_code=None, phone=None, latest_only=False):
    query = Order.query

    if group_code:
        query = query.filter_by(group_code=group_code)
    elif phone:
        query = query.filter_by(customer_phone=phone)
    else:
        return []

    orders = query.order_by(Order.created_at.desc()).all()
    if not orders:
        return []

    if latest_only and not group_code:
        latest_group_code = orders[0].group_code
        orders = [order for order in orders if order.group_code == latest_group_code]

    grouped = []
    grand_total = 0

    for order in orders:
        store = User.query.get(order.seller_id)
        items = [
            {
                "name": item.product_name,
                "quantity": item.quantity,
                "price": item.unit_price,
                "subtotal": round(item.quantity * item.unit_price, 2),
            }
            for item in order.items
        ]
        order_total = round(sum(item["subtotal"] for item in items), 2)
        grand_total += order_total
        grouped.append(
            {
                "order_id": order.id,
                "store_name": store.store_name if store else "Unknown Store",
                "items": items,
                "total": order_total,
                "status": order.status,
            }
        )

    return {
        "orders": grouped,
        "grand_total": round(grand_total, 2),
        "message": "This order will be fulfilled from multiple nearby stores"
        if len(grouped) > 1
        else "This order will be fulfilled from a single store",
    }
