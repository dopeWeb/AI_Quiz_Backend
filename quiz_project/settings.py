"""
Django settings for quiz_project project.

Generated by 'django-admin startproject' using Django 5.1.5.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""
import os
from pathlib import Path
from decouple import config
from dotenv import load_dotenv



# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(os.path.join(BASE_DIR, '.env'))


SECRET_KEY = config("SECRET_KEY") 

DEBUG = False

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',  
    'quiz_app',
    'axes',

]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'axes.middleware.AxesMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
CORS_ALLOW_ALL_ORIGINS = True


ROOT_URLCONF = 'quiz_project.urls'

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

WSGI_APPLICATION = 'quiz_project.wsgi.application'

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases



# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


OPENAI_API_KEY = config("OPENAI_API_KEY", default="")



CORS_ALLOW_CREDENTIALS = True


CSRF_TRUSTED_ORIGINS = ['http://localhost:3000']


CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
]

SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
CSRF_COOKIE_SECURE = True      # For development only; use True in production with HTTPS
SESSION_COOKIE_SECURE = True   # For development only; use True in production with HTTPS

GOOGLE_CLIENT_ID =config("GOOGLE_CLIENT_ID", default="")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "simple": {
            "format": "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        },
    },

    "handlers": {
        # your main Django logs
        "file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "myapp.log",
            "formatter": "simple",
            "level": "DEBUG",
            "encoding": "utf-8",
        },
        # a dedicated file for the frontend‐shim logs
        "frontend_file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "frontend.log",
            "formatter": "simple",
            "level": "INFO",
            "encoding": "utf-8",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
            "level": "DEBUG",
        },
    },

    "loggers": {
        # root logger: captures anything if not caught by more specific loggers
        "": {
            "handlers": ["console", "file"],
            "level": "INFO",
        },
        # your app code
        "myapp": {
            "handlers": ["file"],
            "level": "DEBUG",
            "propagate": False,
        },
        # the logger you’ll use for frontend‐shim POSTs
        "frontend": {
            "handlers": ["frontend_file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}




DATABASES = {
       "default": {
        "ENGINE":   "django.db.backends.postgresql",
        "NAME":     config("POSTGRES_DB"),
        "USER":     config("POSTGRES_USER"),
        "PASSWORD": config("POSTGRES_PASSWORD"),
        "HOST":     config("POSTGRES_HOST"),
        "PORT":     config("POSTGRES_PORT", cast=int),
        "CONN_MAX_AGE": 600,    # keep connections open for 10 minutes

    }
}

FRONTEND_URL = config('FRONTEND_URL')


AUTHENTICATION_BACKENDS = [
    'quiz_project.custom_backend.CaseSensitiveBackend',  # Update the path according to your project structure.
]



AXES_FAILURE_LIMIT = 5

AXES_COOLOFF_TIME = 1  

AXES_USE_USER_AGENT = True

AXES_DISABLE_SUPERUSER_LOCKOUT = False


# Optional: Log axis events at the DEBUG level.
import logging
logging.getLogger('axes.watch_login').setLevel(logging.DEBUG)

