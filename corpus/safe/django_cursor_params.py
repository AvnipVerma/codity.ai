from django.db import connection
from django.http import JsonResponse


def order_detail(request, order_id):
    status = request.GET.get("status", "open")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, total FROM orders WHERE id = %s AND status = %s", [order_id, status])
        row = cursor.fetchone()
    return JsonResponse({"order": row})
