from datetime import timedelta
import random
from django.utils import timezone
from django.contrib.auth import authenticate, login as django_login
from django.core.mail import send_mail
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import AuthUser
from .serializers import AuthUserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.middleware.csrf import get_token
from django.contrib.sessions.models import Session
from django.http import JsonResponse


def generate_random_digits(n=6):
    return "".join(map(str, random.sample(range(10), n)))

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    user = authenticate(request, email=email, password=password)

    if user is not None:
        # User credentials are valid, proceed with code generation and email sending
        my_auth = AuthUser.objects.get(user=user)
        
        # Generate a 6-digit code and set the expiry time to 1 hour from now
        verification_code = generate_random_digits  
        my_auth.otp = verification_code()
        my_auth.otp_expiry_time = timezone.now() + timedelta(hours=1)
        my_auth.save()

        # Send the code via email (use Django's send_mail function)
        send_mail(
            'Verification Code',
            f'Your verification code is: {my_auth.otp}',
            'ludicrouspong@gmail.com',
            [email],
            fail_silently=False,
        )

        # csrf_token = get_token(request)
        response = Response({'detail': 'Verification code sent successfully.'}, status=status.HTTP_200_OK)
        # response.set_cookie("csrftoken", csrf_token)

        # if request.session.session_key:
        #     session_id = request.session.session_key
        # else:
        #     request.session.save()
        #     session_id = request.session.session_key
        # response.set_cookie('sessionid', session_id)

        return response

    return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify(request):
    email = request.data.get('email')
    password = request.data.get('password')
    otp = request.data.get('otp')

    user = authenticate(request, email=email, password=password)

    if user is not None:
        auth_user = AuthUser.objects.get(user=user)

        # Check if the verification code is valid and not expired
        if (
            auth_user.otp == otp and
            auth_user.otp_expiry_time is not None and
            auth_user.otp_expiry_time > timezone.now()
        ):
            # Verification successful, generate access and refresh tokens
            django_login(request, user)
            # Implement your token generation logic here

            # Use djangorestframework_simplejwt to generate tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Reset verification code and expiry time
            auth_user.otp = ''
            auth_user.otp_expiry_time = None
            auth_user.save()

            return Response({'access_token': access_token, 'refresh_token': str(refresh)}, status=status.HTTP_200_OK)

    return Response({'detail': 'Invalid verification code or credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

# Next: verify() otp with session user
# Next: register() new auth_user