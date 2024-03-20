from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('main', '0005_alter_role_rolename'),
    ]

    operations = [
        migrations.RunSQL(
            'CREATE EXTENSION IF NOT EXISTS pg_trgm;', reverse_sql=migrations.RunSQL.noop
        )
    ]
