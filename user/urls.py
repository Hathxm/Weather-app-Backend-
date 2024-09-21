from django.urls import path,include
from .import views
urlpatterns = [
    path('signup', views.Signup.as_view(),name = "signup" ),
    path('login',views.Login.as_view(),name = "login"),
    path('google-login',views.GoogleLogin.as_view(),name = "google-login"),
    path('token/refresh/',views.token_refresh.as_view(),name='token_refresh'),
    path('user-details',views.UserDetailsView.as_view(),name='user-details'),

    




]