from django.contrib import admin
from django.urls import path
from .views import registration_view,activate_email,login,logout,change_password,reset_password,reset_password_confirm

urlpatterns = [
    path('register/',registration_view),
    path('register_confirm/<uidb64>/<token>/', activate_email),
    path('login/',login),
    path('logout/',logout),
    path('change_password/',change_password),
    path('reset_password/',reset_password),
    path('reset_password_confirm/<uidb64>/<token>/',reset_password_confirm),
]
