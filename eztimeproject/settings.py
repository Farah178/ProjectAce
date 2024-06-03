"""
Django settings for eztimeproject project.

Generated by 'django-admin startproject' using Django 3.2.10.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

from pathlib import Path
from datetime import timedelta
import os
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-b+$c%lkixc=a0efyz4+_totmnwzj@#_m)(-xweihk%yu9%xi(@'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ["*",'143.110.184.45', 'https://eztime.thestorywallcafe.com', 'eztime.thestorywallcafe.com', '127.0.0.1',"20.197.54.1","projectaceuat.thestorywallcafe.com","https://projectaceuat.thestorywallcafe.com","www.projectaceuat.thestorywallcafe.com"]

# Application definition

DEFAULT_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]
THIRD_PARTY_APPS = [
    'rest_framework',
    'rest_framework.authtoken',
    # 'django_filters',
    # 'drf_yasg',
    'corsheaders',
    # 'django_celery_results',
    # 'django_celery_beat',
    'import_export',
]
LOCAL_APPS  = [
    'm1',
    'eztimeapp'
]

INSTALLED_APPS  =   DEFAULT_APPS + THIRD_PARTY_APPS + LOCAL_APPS
APPEND_SLASH=False

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'eztimeproject.urls'

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

WSGI_APPLICATION = 'eztimeproject.wsgi.application'

CSRF_TRUSTED_ORIGINS = ['https://projectaceuat.thestorywallcafe.com']

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }



# try:
#     from eztimeproject.local import *
# except ImportError:
#     print("create your own local setting file to use local settings")
#     pass

# DATABASES = {
#     'default': {
#         'ENGINE': 'mssql',
#         'NAME': 'project_ace',  # Database name
#         'USER': 'admin_ace',
#         'PASSWORD': 'Projectace@@123',
#         'HOST': 'ace-db.mysql.database.azure.com',
#         'PORT': '',  # Leave empty or remove this line
#         'OPTIONS': {
#             'driver': 'ODBC Driver 17 for SQL Server',
#             'server': 'ace-db.mysql.database.azure.com',
#             'port': '1433',
#             'database': 'project_ace',
#             'UID': 'admin_ace',
#             'PWD': 'Projectace@@123',
#             'Encrypt': 'yes',
#             'TrustServerCertificate': 'no',
#         },
#     },
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'project_ace',  # Database name
        'USER': 'admin_ace',
        'PASSWORD': 'Projectace@@123',
        'HOST': 'ace-db.mysql.database.azure.com',
        'PORT': '3306',
        'OPTIONS': {
            'ssl': {
                'ca': '/eztime/django/ssl/DigiCertGlobalRootCA.crt.pem',
                }
            }     
        }
}

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = False


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/



# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'




STATIC_URL = '/static/'
MEDIA_URL = '/media/'
STATIC_ROOT="/eztime/static/"

# STATIC_ROOT="/eztime/site/public/static"
# MEDIA_ROOT="/eztime/site/public/media"

# STATICFILES_DIRS = [
#         '/eztime/site/public/static/frontend'
# ] 



EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'farhana@ekfrazo.in'
EMAIL_HOST_PASSWORD = 'brxfauuctuxdefht'
EMAIL_USE_TLS = True
APPLICATION_EMAIL = 'Admin<test@gmail.com>'
DEFAULT_FROM_EMAIL = 'Admin<test@gmail.com>'


SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=10),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=2),
    

    'AUTH_HEADER_TYPES': ('Bearer',),
    
}




JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
# JWT_SECRET_KEY = 'wcwef*rax1mz3gr$f&)gzo@bdbx)rml19ykmz+51*tj!j_yyp-'
CORS_ORIGIN_ALLOW_ALL   = True
CORS_ALLOW_CREDENTIALS  = True

#CELERY setting

CELERY_BROKER_URL = 'redis://127.0.0.1:6379'
# CELERY_RESULT_BACKEND ='redis://127.0.0.1:6379'
CELERY_RESULT_BACKEND ='django-db'
CELERY_ACCET_CONTENT = ['application/json']
CELERY_RESULT_SERIALIZER ='json'
CELERY_TASK_SERIALIZER ='json'
CELERY_TIMEZONE ='Asia/Kolkata'
CELERY_CACHE_BACKEND = 'django-cache'

REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
}





