from django.urls import path
from users.views import SignUpCreateAPIView, CodeVerifyAPIView, UpdateUserAPIView, UpdateUserAvatarAPIView, \
    ResendCodeVerifyAPIView, LoginView, LogoutView, RefreshTokenView

app_name = 'users'

urlpatterns = [
    path('register/', SignUpCreateAPIView.as_view(), name='register'),
    path('login/',LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('refresh/token/', RefreshTokenView.as_view(), name='refresh'),
    path('verify/', CodeVerifyAPIView.as_view(), name='verify'),
    path('verify/resend/', ResendCodeVerifyAPIView.as_view(), name='resend-code'),
    path('update/', UpdateUserAPIView.as_view(), name='update'),
    path('update/avatar/', UpdateUserAvatarAPIView.as_view(), name='avatar')
]
