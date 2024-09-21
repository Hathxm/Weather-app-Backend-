from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework.response import Response
from .serializer import UserSerializer
from rest_framework import status

# Create your views here.

class UserManagement(APIView):
    def get(self, request):
        users = User.objects.filter(is_superuser=False)
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    
    def patch(self,request):
        id=request.data.get('userId')
        print(id)
        user=User.objects.get(id=id)
        if user.is_active==True:
             user.is_active=False
        else:
             user.is_active=True
        user.save()
        return Response({'success':'user updated successfully'},status=status.HTTP_200_OK)
