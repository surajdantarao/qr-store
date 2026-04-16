import json

from flask import Blueprint, render_template, request

from services.fulfillment import get_marketplace_categories, get_marketplace_products

marketplace_bp = Blueprint("marketplace", __name__)


@marketplace_bp.route("/")
def home():
    return render_template("Home.html")


@marketplace_bp.route("/marketplace")
def marketplace():
    search_query = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip() or None
    marketplace_products = get_marketplace_products(search_query=search_query, category=category)
    categories = get_marketplace_categories()

    return render_template(
        "marketplace.html",
        marketplace_products=marketplace_products,
        categories=categories,
        selected_category=category or "",
        search_query=search_query,
        marketplace_products_json=json.dumps(marketplace_products),
    )
