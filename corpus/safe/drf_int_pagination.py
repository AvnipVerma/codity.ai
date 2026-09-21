from django.db import connection
from rest_framework.response import Response
from rest_framework.views import APIView


class RecentEvents(APIView):
    def get(self, request):
        page = int(request.query_params.get("page", 1))
        size = int(request.query_params.get("size", 20))
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT id, kind FROM events ORDER BY id DESC LIMIT {size} OFFSET {(page - 1) * size}")
            rows = cursor.fetchall()
        return Response({"events": rows})
