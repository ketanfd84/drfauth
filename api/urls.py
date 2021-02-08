from django.urls import path
from rest_framework import routers

from api import views

router = routers.DefaultRouter()

router.register('user', views.UserViewSet)

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('change_password/', views.ChangePasswordView.as_view(), name='change_password')
] + router.urls
