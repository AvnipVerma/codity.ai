"""A Django view. `request` is injected by the framework as a parameter."""
from django.db import connection
from django.http import JsonResponse


def search_customers(request):
    name = request.GET.get("name", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, name FROM customers WHERE name LIKE '%%" + name + "%%'")
        rows = cursor.fetchall()
    return JsonResponse({"customers": rows})
