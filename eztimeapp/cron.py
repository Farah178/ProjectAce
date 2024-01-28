from apscheduler.schedulers.background import BackgroundScheduler
import time
from datetime import datetime
from eztimeapp.views import *

def start():
    print("IN cron.py")
    scheduler = BackgroundScheduler(timezone="Asia/Kolkata")
    print("IN cron.py222")
    scheduler.add_job(notificationcenter, 'cron', hour='*', jitter=120)
    print("IN cron.py333")
    scheduler.start()
