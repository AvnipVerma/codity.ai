import os

from rest_framework.response import Response
from rest_framework.views import APIView

MEDIA_ROOT = "/srv/media"


class AvatarUpload(APIView):
    def post(self, request):
        name = request.data["filename"]
        destination = os.path.join(MEDIA_ROOT, "avatars", name)
        with open(destination, "wb") as fh:
            fh.write(request.FILES["avatar"].read())
        return Response({"stored": name})
