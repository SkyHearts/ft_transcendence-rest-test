from django.shortcuts import render, redirect
from django.urls import path
from . import views

app_name = "auth_user"

urlpatterns = [
    path("login/", views.login, name="login"),
    path("verify/", views.verify, name="verify"),
]