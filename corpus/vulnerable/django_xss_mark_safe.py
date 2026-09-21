from django.shortcuts import render
from django.utils.safestring import mark_safe


def profile_preview(request):
    bio = request.POST.get("bio", "")
    html = mark_safe("<div class='bio'>" + bio + "</div>")
    return render(request, "preview.html", {"bio_html": html})
