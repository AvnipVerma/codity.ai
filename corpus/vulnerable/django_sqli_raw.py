from django.db import models
from django.http import JsonResponse


class Person(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)


def people_by_last_name(request):
    last_name = request.GET["last_name"]
    people = Person.objects.raw("SELECT * FROM app_person WHERE last_name = '%s'" % last_name)
    return JsonResponse({"ids": [p.id for p in people]})
