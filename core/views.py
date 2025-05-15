from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from .serializer import RegisterSerializer,VerifyOTPSerializer,LoginSerializer
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from rest_framework.permissions import IsAuthenticated

User = get_user_model()  # ✅ Use PascalCase for class names

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():  # ✅ Add parentheses to call the method
            user = serializer.save()
            return Response({  # ✅ Use Response, not 'response'
                "message": "Register successfully",
                "user": {
                    "username": user.username,
                    "email": user.email
                }
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    def post(Self,request):
        serializer=VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            user=serializer.save()
            return Response({"message":"Otp verified successfully",
                'user':{
                    'username':user.username,
                    'email':user.email,
                    'is_verified':user.is_verified
                }
                },status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self,request):
        serializer=LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data,status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class LogoutVIew(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request):
        try:
            refresh_token=request.data['refresh']
            token=RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message":"logout successfully"},status=status.HTTP_205_RESET_CONTENT)
        except KeyError:
            return Response({"error":"refresh token required"},status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"error":"the token is expired or invalid"},status=status.HTTP_400_BAD_REQUEST)