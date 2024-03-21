from django.db import migrations
from main.management.commands.seeds import numberOfEntities

class Migration(migrations.Migration):

    dependencies = [
        ('main', 'pg_search'),
    ]

    operations = [
        # migrations.RunPython(forwards_func),
        migrations.RunSQL(
            f'ALTER SEQUENCE main_auth_id_seq RESTART WITH {numberOfEntities + 1};'
            f'ALTER SEQUENCE main_user_id_seq RESTART WITH {numberOfEntities + 1};'
        )
    ]
