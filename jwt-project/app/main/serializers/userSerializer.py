from rest_framework import serializers
from main.subModels.user import User
from main.subModels.auth import Auth

class UserSerializer(serializers.HyperlinkedModelSerializer):
    email = serializers.SerializerMethodField()

    def get_email(self, user):
        try:
            auth = Auth.objects.get(id=user.auth_id)
            email = auth.email
        except Auth.DoesNotExist:
            email = None

        return email

    class Meta:
        model = User
        fields = ('id', 'nickname', 'bornDate', 'email', 'auth_id')
