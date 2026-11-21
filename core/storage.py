import mimetypes

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible


@deconstructible
class DatabaseStorage(Storage):
    """Persistent file storage backed by the database (core.StoredFile).

    Serverless hosts such as Vercel only provide an ephemeral, mostly read-only filesystem.
    Storing uploads in the project's PostgreSQL database keeps ID cards and incident photos
    available across cold starts and instances. URLs point at the authenticated /media/ view.
    """

    def _model(self):
        from .models import StoredFile
        return StoredFile

    @staticmethod
    def _clean(name):
        return str(name).replace('\\', '/').lstrip('/')

    def _open(self, name, mode='rb'):
        obj = self._model().objects.filter(name=self._clean(name)).first()
        if obj is None:
            raise FileNotFoundError(name)
        return ContentFile(bytes(obj.content), name=obj.name)

    def _save(self, name, content):
        name = self._clean(name)
        if hasattr(content, 'seek'):
            try:
                content.seek(0)
            except Exception:
                pass
        data = content.read()
        if isinstance(data, str):
            data = data.encode('utf-8')
        content_type = mimetypes.guess_type(name)[0] or 'application/octet-stream'
        self._model().objects.update_or_create(
            name=name,
            defaults={'content': data, 'content_type': content_type},
        )
        return name

    def exists(self, name):
        return self._model().objects.filter(name=self._clean(name)).exists()

    def delete(self, name):
        self._model().objects.filter(name=self._clean(name)).delete()

    def size(self, name):
        obj = self._model().objects.filter(name=self._clean(name)).first()
        if obj is None:
            raise FileNotFoundError(name)
        return len(bytes(obj.content))

    def url(self, name):
        base = settings.MEDIA_URL if settings.MEDIA_URL.endswith('/') else settings.MEDIA_URL + '/'
        return base + self._clean(name)

