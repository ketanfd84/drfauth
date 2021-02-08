from django.contrib.auth.models import User
import django.contrib.auth.password_validation as validators
from rest_framework import serializers, exceptions
from rest_framework.views import APIView


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('username', 'email')


class RegisterUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    def validate(self, data):
        user = User(**data)

        password = data.get('password')

        errors = dict()
        try:
            validators.validate_password(password=password, user=User)

        except exceptions.ValidationError as e:
            errors['password'] = list(e)

        if errors:
            raise serializers.ValidationError(errors)

        return super(RegisterUserSerializer, self).validate(data)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=50)
    new_password = serializers.CharField(max_length=50)

    def validate(self, data):

        user = self.context.get('request').user if self.context.get('request') else None

        password = data.get('new_password')

        errors = dict()
        try:
            validators.validate_password(password=password, user=user)

        except exceptions.ValidationError as e:
            errors['password'] = list(e)

        if errors:
            raise serializers.ValidationError(errors)

        return super(ChangePasswordSerializer, self).validate(data)


class ChangeEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = self.context.get('request').user if self.context.get('request') else None
        if not user:
            raise exceptions.AuthenticationFailed('Please Login')
        password = data.get('password')
        if not user.check_password(password):
            raise exceptions.ValidationError({'password': 'Password Not match'})

        return super(ChangeEmailSerializer, self).validate(data)


class ChangeUsernameSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = self.context.get('request').user if self.context.get('request') else None
        if not user:
            raise exceptions.AuthenticationFailed('Please Login')
        password = data.get('password')
        if not user.check_password(password):
            raise exceptions.ValidationError({'password': 'Password Not match'})

        return super(ChangeUsernameSerializer, self).validate(data)
