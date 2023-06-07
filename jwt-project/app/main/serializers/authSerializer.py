from rest_framework import serializers
from main.serializers.roleSerializer import RoleSerializer
from main.subModels.auth import Auth
from main.subModels.role import Role

class AuthSerializer(serializers.ModelSerializer):
    roles = RoleSerializer(many=True)

    class Meta:
        model = Auth
        fields = '__all__'
        # ('id','username', 'email', 'password', 'roles')

    def create(self, data):
        roles = data.pop('roles')
        auth = Auth.objects.create(**data)
        for role in roles:
            print(role)
            roleObj = Role.objects.get(roleName=role["roleName"])
            auth.roles.add(roleObj)
        return auth