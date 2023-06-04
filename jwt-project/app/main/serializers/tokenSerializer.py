from rest_framework import serializers
from main.subModels.token import Token

class TokenSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Token
        fields = ('key', 'auth_id')
