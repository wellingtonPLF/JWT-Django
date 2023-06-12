from django_seed import Seed
from main.subModels.user import User
from main.subModels.auth import Auth
from main.subModels.token import Token
from main.subModels.role import Role
from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
import bcrypt

# python manage.py seeds

class Command(BaseCommand):

    def handle(self, *args, **options):

        seeder = Seed.seeder()
        roles = ['ROLE_USER', 'ROLE_ADMIN']
        password = '12345678'
        numberOfEntities = 3

        for index in range(len(roles)):
            try:
                Role.objects.get(roleName=roles[index])
            except:
                obj = {
                    'id': index + 1,
                    'roleName': f'{roles[index]}'
                }
                role = Role(**obj)
                role.save()

        role = Role.objects.get(id=2)

        for index in range(numberOfEntities):
            try:
                Auth.objects.get(id=index + 1)
            except:
                salt = bcrypt.gensalt(10)
                obj = {
                    'id': index + 1,
                    'email': seeder.faker.email(),
                    'username': seeder.faker.user_name(),
                    'password': make_password(password, salt=salt, hasher='bcrypt')
                }
                auth = Auth(**obj)
                auth.save()
                auth.roles.set([role])

        for index in range(numberOfEntities):
            try:
                User.objects.get(id=index + 1)
            except:
                obj = {
                    'id': index + 1,
                    'nickname': seeder.faker.name(),
                    'bornDate': seeder.faker.date_between(start_date='-20y', end_date='today').strftime('%Y-%m-%d'),
                    'auth': Auth.objects.get(id=index + 1)
                }
                user = User(**obj)
                user.save()
