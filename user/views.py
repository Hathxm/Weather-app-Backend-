from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
import jwt
from datetime import timedelta
from django.utils.timezone import now
from superadmin.serializer import UserSerializer

# Create your views here.

class Signup(APIView):
    def post(self,request):
        print("ye baby")
        try:
            # Extract data from the request
            username = request.data.get('username')
            email = request.data.get('email')
            password = request.data.get('password')
          

            # Basic validation
            if not email or not password:
                return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the user already exists
            if User.objects.filter(username=username).exists():
                return Response({"error": "User with this username already exists"}, status=status.HTTP_400_BAD_REQUEST)
            
            if User.objects.filter(email=email).exists():
                return Response({"error": "User with this email already exists"}, status=status.HTTP_400_BAD_REQUEST)

            # Create a new user
            user = User.objects.create(
                username=username,
                email=email,
                password=make_password(password)  # Hash the password before saving it
            )

            # Return a success response
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Log the exception
            print(f"An error occurred: {e}")

            # Return a generic error response
            return Response({"error": "An error occurred while creating the user"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class Login(APIView):
    def post(self, request):
        try:
            # Extract data from the request
            username = request.data.get('username')
            password = request.data.get('password')

            # Basic validation
            if not username or not password:
                return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the user exists
            user = authenticate(username=username, password=password)

            if user is None:
                return Response({"error": "Invalid username or password"}, status=status.HTTP_400_BAD_REQUEST)
            
            refresh = RefreshToken.for_user(user)
       

            # Successful authentication
            return Response({
                "username":user.username,
                "email":user.email,
                "id":user.id,
                "message": "Login successful",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "is_superuser": user.is_superuser  # Add this line
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Log the exception
            print(f"An error occurred: {e}")

            # Return a generic error response
            return Response({"error": "An error occurred while logging in"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
   
class GoogleLogin(APIView):
    def post(self, request):
        try:
            token = request.data.get('token')
            if not token:
                return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Verify the token with Google
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), settings.GOOGLE_CLIENT_ID)

            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                return Response({'error': 'Invalid token issuer'}, status=status.HTTP_400_BAD_REQUEST)

            email = idinfo.get('email')
            username = idinfo.get('sub')  # Unique identifier from Google

            # Check if the user already exists
            user = User.objects.filter(username=email,email=email).first()
            

            if user:
                # User exists, generate tokens with user's data
                is_authenticated = user.is_active
                is_superuser = user.is_superuser
                user_name = user.username,
                user_mail = user.email,
                id = user.id,
            
            else:
                # User does not exist, set superuser status to False
                user = User.objects.filter(email=email,is_superuser=True)
                if user:
                    return Response("This email is in use for specific purpose",status=status.HTTP_400_BAD_REQUEST)
                else:
                    user = User.objects.create(username=email,email=email,is_superuser=False)
                    is_authenticated = user.is_active
                    is_superuser = False
                    user_name = email,
                    user_mail = email,
                    id = user.id,

            # Create JWT tokens
            refresh = RefreshToken.for_user(user)
         
            return Response({
                'username': user_name,
                'email':user_mail,
                'is_authenticated':is_authenticated,
                'id':id,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'is_superuser': is_superuser
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            # Log the exception
            print(f"An error occurred: {e}")

            # Return a generic error response
            return Response({"error": "An error occurred while logging in"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class token_refresh(APIView):
   print("token refreshed")
   def post(self, request):
       refresh_token = request.data.get('refresh')
       if not refresh_token:
           return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
       
       try:
           refresh = RefreshToken(refresh_token)
           new_access_token = str(refresh.access_token)
           new_refresh_token = str(refresh)

           # Return the new tokens
           return Response({
               'access': new_access_token,
               'refresh': new_refresh_token,
           }, status=status.HTTP_200_OK)
       except Exception as e:
           print(e)
           return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class UserDetailsView(APIView):
    def get(self, request):
        user = request.user  # Assuming user authentication is implemented
        print(user)
        if user.is_authenticated:
            user_details = User.objects.get(username=user)
            serialized_data = UserSerializer(user_details)
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)