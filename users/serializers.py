from rest_framework import serializers
from django.core.validators import FileExtensionValidator
from django.utils.translation import gettext as _
from rest_framework import serializers
import re
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from shared.utils import send_code_to_email, send_code_to_phone
from users.models import UserModel, VIA_EMAIL, VIA_PHONE, PHOTO, DONE


class SignUpSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(max_length=128, required=False)

    uuid = serializers.IntegerField(read_only=True)
    auth_type = serializers.CharField(read_only=True, required=False)
    auth_status = serializers.CharField(read_only=True, required=False)

    class Meta:
        model = UserModel
        fields = ['uuid', 'auth_type', 'auth_status']

    def validate(self, data):
        data = self.auth_validate(data=data)
        return data

    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        code = user.create_verify_code(user.auth_type)

        if user.auth_type == VIA_EMAIL:
            send_code_to_email(user.email, code)
        else:
            send_code_to_phone(user.phone_number, code=code)
        user.save()
        return user

    @staticmethod
    def auth_validate(data):
        user_input = str(data['email_phone_number']).lower()
        if user_input.endswith('@gmail.com'):
            data = {
                'email': user_input,
                'auth_type': VIA_EMAIL
            }
        elif user_input.startswith("+"):
            data = {
                'phone_number': user_input,
                'auth_type': VIA_PHONE
            }
        else:
            data = {
                'success': False,
                'message': "Please enter a valid phone number or email"
            }
            raise serializers.ValidationError(data)
        return data

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data['access_token'] = instance.token()['access_token']
        return data


class UpdateUserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=255, write_only=True, required=True)
    last_name = serializers.CharField(max_length=255, write_only=True, required=True)
    username = serializers.CharField(max_length=255, write_only=True, required=True)
    password = serializers.CharField(max_length=128, write_only=True, required=True)
    confirm_password = serializers.CharField(max_length=128, write_only=True, required=True)

    class Meta:
        model = UserModel
        fields = ['first_name', 'last_name', 'username', 'password', 'confirm_password']

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            response = {
                "success": False,
                "message": "Passwords don't match"
            }
            raise serializers.ValidationError(response)

        return attrs

    def validate_username(self, username):
        if UserModel.objects.filter(username=username).exists():
            response = {
                "success": False,
                "message": "Username is already gotten"
            }
            raise serializers.ValidationError(response)
        return username

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.password = validated_data.get('password', instance.password)

        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
            instance.auth_status = DONE
            instance.save()
        return instance


class UserAvatarSerializer(serializers.Serializer):
    avatar = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=['png', 'jpg', 'jpeg'])])

    def update(self, instance, validated_data):
        instance.avatar = validated_data.get('avatar', instance.avatar)
        instance.save()
        return instance


def validate_username(value):
    if not re.match(r'^[a-zA-Z0-9_]+$', value):
        raise ValidationError(
            'Foydalanuvchi nomi faqat harflar, raqamlar va tag chiziq (_) dan iborat bo\'lishi mumkin.')


def validate_password(value):
    if len(value) < 8:
        raise ValidationError('Parol kamida 8 ta belgidan iborat bo\'lishi kerak.')
    if not re.search(r'[A-Z]', value):
        raise ValidationError('Parolda kamida bitta katta harf bo\'lishi kerak.')
    if not re.search(r'[a-z]', value):
        raise ValidationError('Parolda kamida bitta kichik harf bo\'lishi kerak.')
    if not re.search(r'[0-9]', value):
        raise ValidationError('Parolda kamida bitta raqam bo\'lishi kerak.')
    if not re.search(r'[\W_]', value):
        raise ValidationError('Parolda kamida bitta maxsus belgi bo\'lishi kerak.')


def validate_email(email):
    validator = EmailValidator()
    try:
        validator(email)
    except ValidationError as e:
        raise ValidationError("Invalid email address.") from e


def validate_phone_number(phone_number):
    phone_regex = r'^\+?1?\d{9,15}$'
    validator = RegexValidator(phone_regex, "Invalid phone number format.")
    validator(phone_number)


class LoginSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(max_length=255, required=True)

    def validate(self, attrs):
        userinput = attrs.get('userinput')
        if userinput.endswith('@gmail.com'):
            user = UserModel.objects.filter(email=userinput).first()
        elif userinput.startswith('+'):
            user = UserModel.objects.filter(phone_number=userinput).first()
        else:
            user = UserModel.objects.filter(username=userinput).first()

        if user is None:
            response = {
                "success": False,
                "message": "Username or Password is invalid"
            }
            raise serializers.ValidationError(response)
        auth_user = authenticate(username=user.username, password=attrs['password'])
        if auth_user is None:
            response = {
                "success": False,
                "message": "Username or Password is invalid"
            }
            raise serializers.ValidationError(response)

        response = {
            "success": True,
            "access_token": auth_user.token()['access_token'],
            "refresh_token": auth_user.token()['refresh_token']
        }
        return response

    def validate_user(self, value):
        user_status = value.status
        if user_status not in ['PHOTO', 'DONE']:
            raise ValidationError("User status is not valid for login.")
        return value


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
