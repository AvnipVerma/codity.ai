import subprocess

from django.http import HttpResponse
from django.views import View


class PingView(View):
    def get(self, request, *args, **kwargs):
        host = request.GET.get("host", "localhost")
        result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
        return HttpResponse(result.stdout, content_type="text/plain")
