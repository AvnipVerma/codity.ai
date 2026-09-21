from django.http import HttpResponse
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe


def greeting(request):
    name = request.GET.get("name", "friend")
    banner = format_html("<h1>Hello {}</h1>", name)
    footer = mark_safe("<p>Signed in as " + escape(name) + "</p>")
    return HttpResponse(banner + footer)
