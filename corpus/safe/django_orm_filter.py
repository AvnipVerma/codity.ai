from django.db import models
from django.http import JsonResponse


class Person(models.Model):
    last_name = models.CharField(max_length=50)


def people_by_last_name(request):
    last_name = request.GET["last_name"]
    people = Person.objects.filter(last_name=last_name).order_by("id")
    return JsonResponse({"ids": list(people.values_list("id", flat=True))})
