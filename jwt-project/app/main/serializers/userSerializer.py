from rest_framework import serializers
from main.subModels.user import User
from main.subModels.auth import Auth
from django.forms.models import model_to_dict

class UserSerializer(serializers.ModelSerializer):
    email = serializers.SerializerMethodField()
    auth_id = serializers.IntegerField() 

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

    def create(self, data):
        auth_id = data.get("auth_id")
        try:
            User.objects.get(auth_id=auth_id)
            raise serializers.ValidationError("User already exist.")
        except User.DoesNotExist:
            user = {
                'nickname': data["nickname"], 
                'bornDate': data["bornDate"], 
            }
            auth = Auth.objects.get(id=auth_id)
            authData = model_to_dict(auth)
            authData = {key: value for key, value in authData.items() if key != 'roles'}
            auth = Auth(**authData)
            user = User(**user)
            user.auth = auth
            user.save()
            return user
