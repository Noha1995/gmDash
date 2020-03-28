'''Use this for development'''
import os
from .base import *
import django_heroku
ALLOWED_HOSTS += ['Comfortzone-env.kkrfxvtxh7.eu-west-1.elasticbeanstalk.com', '127.0.0.1', 'localhost']
DEBUG = True

WSGI_APPLICATION = 'home.wsgi.dev_local.application'

if 'RDS_HOSTNAME' in os.environ:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.mysql',
            'HOST': os.environ['RDS_HOSTNAME'],
            'PORT': os.environ['RDS_PORT'],
            'USER': os.environ['RDS_USERNAME'],
            'PASSWORD': os.environ['RDS_PASSWORD'],
            'NAME': os.environ['RDS_DB_NAME'],

            'OPTIONS': {
                'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"
            }
        }
    }
else:
    # Database
    # https://docs.djangoproject.com/en/1.11/ref/settings/#databases

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        }
    }

django_heroku.settings(locals())