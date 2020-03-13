from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from .utils import send_email_activation,send_email_reset_password,decode_id,activation_token
from .serializers import RegistrationSerializer,PasswordChangeSerializer,LoginSerializer, PasswordResetSerializer,PasswordResetConfirmSerializer
# Create your views here.


@api_view(['POST',])
def registration_view(request):
    if request.method == 'POST':
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            if not user.is_active:
                send_email_activation(user)
                return Response(data={'data': 'Confirm your email address to complete the registration'},status=status.HTTP_200_OK)
            else:
                return Response(data={'data': 'Successfully created'},status=status.HTTP_201_CREATED)
        else:
            return Response(data=serializer.errors,status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET',])
def activate_email(request, uidb64, token):
    try:
        uid = decode_id(uidb64)
        user = User.objects.get(pk=uid)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    if activation_token.check_token(user=user,token=token):
        user.is_active = True
        user.save()
        return Response(data={'detail': 'Thank you for your email confirmation. Now you can login your account.'},status=status.HTTP_201_CREATED)
    return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST',])
def login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        token = serializer.save()
        return Response(data={'Token': token},status=status.HTTP_200_OK)


@api_view(['POST',])
@permission_classes([IsAuthenticated])
def logout(request):
    request.user.auth_token.delete()
    return Response(status=status.HTTP_200_OK)


@api_view(['POST',])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = PasswordChangeSerializer(data=request.data,context=request)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    user.auth_token.delete()
    token, _ = Token.objects.get_or_create(user=user)
    # return new token
    return Response({'Token': token.key}, status=status.HTTP_200_OK)


@api_view(['POST',])
def reset_password(request):
    serializer = PasswordResetSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    send_email_reset_password(serializer.validated_data)
    return Response({'detail': 'Password reset confirmation was sent to your email'})


@api_view(['POST',])
def reset_password_confirm(request, uidb64, token):
    user = User.objects.get(id=decode_id(uidb64))
    serializer = PasswordResetConfirmSerializer(data=request.data,context={'user': user})
    serializer.is_valid(raise_exception=True)
    token = serializer.save()
    return Response(data={'Token': token},status=status.HTTP_200_OK)




