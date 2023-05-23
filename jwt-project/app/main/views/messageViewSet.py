from main.models.message import Message
from ..serializers import MessageSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets

class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer