from django.contrib import admin
from django.http import JsonResponse
from django.urls import path, include


def health(request):
    return JsonResponse({"status": "ok"})

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", health),             # ← simple health endpoint
    path('api/', include('quiz_app.urls')),  # prefix your quiz API with /api/
]
