release: python manage.py migrate
web: gunicorn home.wsgi.dev_local --timeout 300 --log-file -
#web: waitress-serve --port=80 home.wsgi.dev_local:application