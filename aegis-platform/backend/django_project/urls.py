from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from core.views import health_check, readiness_check

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    path('health/', health_check, name='health-check'),
    path('ready/', readiness_check, name='readiness-check'),
    path('api/v1/auth/', include('users.urls')),
    path('api/v1/projects/', include('projects.urls')),
    path('api/v1/scans/', include('scans.urls')),
    path('api/v1/vulnerabilities/', include('vulnerabilities.urls')),
    path('api/v1/assets/', include('assets.urls')),
    path('api/v1/compliance/', include('compliance.urls')),
    path('api/v1/knowledge/', include('knowledge.urls')),
    path('api/v1/notifications/', include('notifications.urls')),
    path('api/v1/audit/', include('audit.urls')),
    path('api/v1/system/', include('system.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
