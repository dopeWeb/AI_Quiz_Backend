"""
WSGI config for quiz_project project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

import os, sys
from django.core.wsgi import get_wsgi_application


sys.path.append(r"D:\JohnBryce\ProjecBackend_Finall")


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "quiz_project.settings")


application = get_wsgi_application()
