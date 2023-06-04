from rest_framework import serializers
from main.subModels.auth import Auth

class AuthSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Auth
        fields = ('id','username', 'email', 'password')
