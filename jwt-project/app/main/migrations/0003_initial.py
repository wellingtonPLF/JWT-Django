# Generated by Django 4.2.1 on 2023-06-02 14:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('main', '0002_remove_token_auth_remove_user_auth_delete_auth_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Auth',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('username', models.CharField(max_length=50)),
                ('password', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('roleName', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nickname', models.CharField(max_length=50)),
                ('bornDate', models.DateField()),
                ('auth', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.auth')),
            ],
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(max_length=100)),
                ('auth', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.auth')),
            ],
        ),
        migrations.AddField(
            model_name='auth',
            name='roles',
            field=models.ManyToManyField(to='main.role'),
        ),
    ]