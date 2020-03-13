from rest_framework import serializers
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from Wanderlance import settings


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email','username', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self,data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError({'data': 'Passwords must matches'})
        if len(User.objects.filter(email=self.validated_data['email'])) != 0:
            raise serializers.ValidationError({'data': 'Email is busy'})
        validate_password(data['password'])
        return data

    def save(self):
        user = User(email=self.validated_data['email'],username=self.validated_data['username'])
        password = self.validated_data['password']

        user.set_password(password)

        if settings.EMAIL_CONFIRM:
            user.is_active = False
        user.save()
        return user


class PasswordChangeSerializer(serializers.Serializer):

    old_password = serializers.CharField(write_only=True, required=True)
    new_password1 = serializers.CharField(write_only=True, required=True)
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context.user
        if not user.check_password(value):
            raise serializers.ValidationError('Your old password was entered incorrectly. Please enter it again.')
        return value

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': "The two password fields didn't match."})
        validate_password(data['new_password1'], self.context.user)
        return data

    def save(self, **kwargs):
        password = self.validated_data['new_password1']
        user = self.context.user
        user.set_password(password)
        user.save()
        return user




class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self,data):
        user = authenticate(username=data['username'],password=data['password'])
        if not user:
            raise serializers.ValidationError({'data': 'Username or password is wrong'})
        return user

    def save(self):
        token, _ = Token.objects.get_or_create(user=self.validated_data)
        return token.key


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self,data):
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError({'detail': 'Wrong email'})
            return None
        return user

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password1 = serializers.CharField(write_only=True, required=True)
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        validate_password(password=data['new_password1'])
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'detail': 'Passwords must match'})
        return data

    def save(self):
        user = self.context['user']
        password = self.validated_data['new_password1']
        user.set_password(password)
        user.auth_token.delete()
        token, _ = Token.objects.get_or_create(user=user)
        return token.key







