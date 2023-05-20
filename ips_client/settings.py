"""
Django settings for ips_client project.

Generated by 'django-admin startproject' using Django 4.2.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os
from dotenv import load_dotenv
import datetime

load_dotenv()
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-o_($$gteswa7@mev2cx^*hrv^wvwjg3*lj&xn+@+uzni1f1x-('

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    #inner apps 
    "rules.apps.RulesConfig",
    "user_manager.apps.UserManagerConfig",
    #third party
    "rest_framework",
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ips_client.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ips_client.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": os.getenv("IPS_CLIENT_POSTGRES_DB"),
        "USER": os.getenv("IPS_CLIENT_POSTGRES_USER"),
        "PASSWORD": os.getenv("IPS_CLIENT_POSTGRES_PASSWORD"),
        "HOST": os.getenv("IPS_CLIENT_POSTGRES_HOST"),
        "PORT": os.getenv("IPS_CLIENT_POSTGRES_PORT"),
    }
}


# JWT_AUTH = {
#     'JWT_EXPIRATION_DELTA': datetime.timedelta(hours=10)
# }

# #Rest frame work

# REST_FRAMEWORK = {
#     'DEFAULT_AUTHENTICATION_CLASSES': (
#         'rest_framework_simplejwt.authentication.JWTAuthentication',
#     )
# }


AUTH_USER_MODEL = "user_manager.Users"


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


IPS_CLIENT_SERVER_URL=os.getenv("IPS_CLIENT_SERVER_URL")
IPS_CLIENT_SNORT_RULES_PATH=os.getenv("IPS_CLIENT_SNORT_RULES_PATH")
IPS_CLIENT_SNORT_CONF_PATH=os.getenv("IPS_CLIENT_SNORT_CONF_PATH")

CORS_ORIGIN_WHITELIST = [
    'http://localhost:3000',
]

SERVER_SIDE_EMAIL='mohammadali@gmail.com'
SERVER_SIDE_PASSWORD='mohammadali'
SERVER_SIDE_ACCESS_TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNjg1NDM5MjQwLCJpYXQiOjE2ODQ1NzUyNDAsImp0aSI6IjBiYzg4ZjI3NzY5NDRjZmE4MTBlOWZlNDYyNjEzMGU1IiwidXNlcl9pZCI6ImY4ZjMxMGM5LTA0MzItNDYyZC04YzljLTIwYTAwNDRiM2ZhOSJ9.0EQQZAaaRSYbkTjN3FdIdS_nh89jtn4FySmA9mH_1MA'