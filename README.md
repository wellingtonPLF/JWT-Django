# JWT-Django
Authentication using django framework. (⚙️)

## Steps:
- `cd app`
- `python -m venv venv`
- `.\venv\Scripts\activate`

- `pip install -r requirements.txt`
- `pipenv install django`

## requirements.txt:
- `pipenv`
- `django-seed`
- `bcrypt`
- `djangorestframework-simplejwt`
- `djangorestframework`
- `django-cors-headers`
- `psycopg2`
- `python-decouple`
- `django-extensions`

## Crie um arquivo .env ao lado do manage.py

- SECRET_KEY=my-super-secret-key
- DEBUG=True
- POSTGRES_DB=
- USERNAME=
- PASSWORD=

## Remove db.sqlite3 and update

- - Após remoção:
- python manage.py migrate
- python manage.py seeds

## Run 
python .\manage.py runserver
