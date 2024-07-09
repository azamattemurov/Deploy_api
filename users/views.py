from django.shortcuts import render
from rest_framework import generics, status
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from shared.utils import send_code_to_email
from users.models import UserModel, ConfirmationModel, CODE_VERIFIED, DONE, PHOTO, VIA_EMAIL
from rest_framework.permissions import AllowAny, IsAuthenticated

from users.serializers import SignUpSerializer, UpdateUserSerializer, UserAvatarSerializer, LoginSerializer, \
    LogoutSerializer


class SignUpCreateAPIView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SignUpSerializer
    model = UserModel


class CodeVerifyAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = request.data.get('code')

        verification_code = ConfirmationModel.objects.filter(
            user_id=user.id, code=code, is_confirmed=False, expiration_time__gte=timezone.now())
        if verification_code.exists():
            user.auth_status = CODE_VERIFIED
            user.save()

            verification_code.update(is_confirmed=True)

            response = {
                'success': True,
                'message': "Your code is successfully verified.",
                'auth_status': user.auth_status,
            }
            return Response(response, status=status.HTTP_200_OK)
        else:
            response = {
                'success': False,
                'message': "Validation code is not valid"
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class ResendCodeVerifyAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = self.request.user

        verification_code = ConfirmationModel.objects.filter(
            is_confirmed=False, user_id=user.id, expiration_time__gte=timezone.now())

        if verification_code.exists():
            response = {
                'success': False,
                'message': "Your have already verified your code."
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

        self.send_code()
        response = {
            'success': True,
            'message': "New code is send"
        }
        return Response(response, status=status.HTTP_200_OK)

    def send_code(self):
        user = self.request.user
        new_code = user.create_verify_code(verify_type=user.auth_type)
        if user.auth_type == VIA_EMAIL:
            send_code_to_email(user.email, new_code)
        else:
            send_code_to_email(user.phone_number, new_code)


class UpdateUserAPIView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UpdateUserSerializer
    http_method_names = ['put', 'patch']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(UpdateUserAPIView, self).update(request, *args, **kwargs)
        response = {
            'success': True,
            'message': "Your account has been updated.",
            'auth_status': self.request.user.auth_status,
        }
        return Response(response, status=status.HTTP_202_ACCEPTED)

    def partial_update(self, request, *args, **kwargs):
        super(UpdateUserAPIView, self).partial_update(request, *args, **kwargs)
        response = {
            'success': True,
            'message': "Your account has been updated.",
        }
        return Response(response, status=status.HTTP_202_ACCEPTED)


class UpdateUserAvatarAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = UserAvatarSerializer(data=request.data)

        if serializer.is_valid():
            serializer.update(user, serializer.validated_data)
            response = {
                "success": True,
                "message": "Updated successfully",
                "auth_status": "PHOTO"
            }
            return Response(response, status=status.HTTP_202_ACCEPTED)
        else:
            response = {
                "success": False,
                "message": "Invalid request",
                "errors": serializer.errors
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        refresh = self.request.data['refresh']
        token = RefreshToken(token=refresh)
        token.blacklist()
        response = {
            'success': True,
            'message': "Logged out successfully",
        }
        return Response(response, status=status.HTTP_200_OK)


class RefreshTokenView(TokenRefreshView):
    serializer_class = TokenRefreshSerializer
