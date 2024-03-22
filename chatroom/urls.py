from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("game/<str:room_name>/", views.room, name="room"),
    path("lobby/", views.lobby, name="lobby"),
]