from django.contrib.auth import logout
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework import generics, status
from rest_framework.decorators import action

from api.serializers import UserSerializer, RegisterUserSerializer, ChangePasswordSerializer, ChangeEmailSerializer, \
    ChangeUsernameSerializer


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    @action(methods=['post'], detail=True)
    def change_email(self, request, *args, **kwargs):
        serializer = ChangeEmailSerializer(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            request.user.email = serializer.validated_data.get('email')
            request.user.save()
            return Response({'Email Updated Successfully'}, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True)
    def change_username(self, request, *args, **kwargs):
        serializer = ChangeUsernameSerializer(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            request.user.email = serializer.validated_data.get('email')
            request.user.save()
            return Response({'Email Updated Successfully'}, status=status.HTTP_200_OK)


class RegisterView(generics.CreateAPIView):
    """
    An endpoint for register user.
    """
    authentication_classes = ()
    permission_classes = ()
    queryset = User.objects.all()
    serializer_class = RegisterUserSerializer


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)

            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):

    def get(self, request, *args, **kwargs):
        Token.objects.filter(user=request.user).delete()
        logout(request)
        return Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)
