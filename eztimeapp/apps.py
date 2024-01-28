from django.apps import AppConfig


class EztimeappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'eztimeapp'

    def ready(self):
        print("Passss schedule")
        from eztimeapp import cron
        cron.start()