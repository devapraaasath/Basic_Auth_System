from django.urls import path
from .views import RegisterView,VerifyOTPView,LoginView,LogoutVIew
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns=[
    path('register/',RegisterView.as_view(),name='register'),
    path('verify/',VerifyOTPView.as_view(),name='verify'),
    path('login/',LoginView.as_view(),name='login'),
    path('logout/',LogoutVIew.as_view(),name='logout'),
    path('refresh/',TokenRefreshView.as_view(),name='refresh'),

]