from flask import Blueprint, request

from .repository import find_by_status, find_orders_for

bp = Blueprint("shop", __name__)


@bp.route("/customers/orders")
def customer_orders():
    customer = request.args["customer_id"]
    return {"orders": find_orders_for(customer)}


@bp.route("/orders/by-status")
def orders_by_status():
    return {"orders": find_by_status(request.args["status"])}
