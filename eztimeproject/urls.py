from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.staticfiles.views import serve
from django.views.generic.base import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('eztimeapp.urls')),
    path('api/', include('m1.urls')),
    re_path(r'^$', serve, kwargs={'path': 'index.html'}),    
    re_path(r'^(?!/?static/)(?!/?media/)(?P<path>.*\..*)$',
            RedirectView.as_view(url='/static/%(path)s', permanent=False)),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + [
    re_path(r'^.*', serve, kwargs={'path': 'index.html'}),
]
