from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from .models import OTP
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken


# ⚠️ FIX: You missed calling the function with parentheses
User = get_user_model()  # NOT User = get_user_model

class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, data):
        # ✅ Check if password and confirm_password match
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        # ⚠️ FIX: Typo in 'is_verified' (you wrote 'is_verifed')
        validated_data.pop('confirm_password')

        # ✅ Use create_user to hash the password
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_verified=False  # This marks the user as unverified until OTP is confirmed
        )

        # ✅ Generate and save OTP
        otp_code = get_random_string(length=6, allowed_chars='0123456789')
        OTP.objects.create(user=user, code=otp_code)

        print(f"OTP for {user.email} - {otp_code}")  # Simulate sending OTP by email or SMS
        return user


class VerifyOTPSerializer(serializers.Serializer):
    username=serializers.CharField()
    code=serializers.CharField(max_length=6)

    def validate(self,data):
        try:
            user=User.objects.get(username=data['username'])
           
        except User.DoesNotExist:
            raise serializers.ValidationError('username does not exists')
        
        try:
            otp=OTP.objects.filter(user=user).latest('created_at')

        except OTP.DoesNotExist:
            raise serializers.ValidationError('otp does not exists')   
        
        if otp.code !=data['code']:
            raise serializers.ValidationError("otp is invalid")
        
        if otp.is_expired():
            raise serializers.ValidationError("otp is expired")
        
        data['user']=user
        return data

    def save(self)   :
        user=self.validated_data['user']
        user.is_verified=True
        user.save()
        return  user


class LoginSerializer(serializers.Serializer):
    identifier=serializers.CharField()
    password=serializers.CharField(write_only=True)

    def validate(self, data):
        identifier=data.get("identifier")
        password=data.get("password")

        try:
            user=User.objects.get(username=identifier)
        except User.DoesNotExist:
            try:
                user=User.objects.get(email=identifier)
            except User.DoesNotExist:
                raise serializers.ValidationError("the given username or the email is invalid , user not found")
        if not user.is_verified:
            raise serializers.ValidationError("user is not verified")
        if not user.check_password(password):
            raise serializers.ValidationError("password is invalid")
        
        refresh=RefreshToken.for_user(user)

        return {
            'refresh':str(refresh),
            'access':str(refresh.access_token),
            'user':{
                'user':user.username,
                'email':user.email,
                'role':user.role
            }
        }