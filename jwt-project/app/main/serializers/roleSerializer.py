from rest_framework import serializers
from main.subModels.role import Role

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'
        