from django.contrib import admin
from django.urls import path, re_path, include
from django.views.generic import RedirectView
from django.views.static import serve
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.staticfiles.views import serve as static_serve

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('eztimeapp.urls')),
    path('api/', include('m1.urls')),

re_path(r'^(?!/?static/)(?!/?media/)(?P<path>.*\..*)$', RedirectView.as_view(url='/static/%(path)s', permanent=False)),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Final catch-all pattern to serve index.html for single-page applications
urlpatterns += [re_path(r'^.*$', static_serve, {'path': 'index.html'})]