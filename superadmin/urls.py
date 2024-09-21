from django.urls import path,include
from .import views
urlpatterns = [
    path('user-management', views.UserManagement.as_view(),name = "user-management" ),





]