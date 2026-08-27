from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from core.views import health_check, readiness_check


urlpatterns = [
    path("admin/", admin.site.urls),

    # API documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),

    # Platform health
    path("health/", health_check, name="health-check"),
    path("ready/", readiness_check, name="readiness-check"),

    # Django-owned API surface:
    # users.urls already contains the "auth/*" routes.
    path("api/v1/", include("users.urls")),

    # User management routes.
    path("api/v1/users/", include("users.management_urls")),

    # Reports are persisted and authorized by Django.
    path("api/v1/reports/", include("reports.urls")),
]


if settings.DEBUG:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT,
    )
    urlpatterns += static(
        settings.STATIC_URL,
        document_root=settings.STATIC_ROOT,
    )
