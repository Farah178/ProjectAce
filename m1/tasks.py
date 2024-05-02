# from celery import shared_task
import time
from time import sleep
from .models import *
from datetime import datetime, timezone, timedelta





# @shared_task(bind = True)
# def auto_approve_timesheet(self):
#     print("qwertyuiuytredrtyuiuytrewertyui")
#     return "DONE"
    # try:
    #     timesheet = TimeSheets.objects.get(id=timesheet_id)
    #     if timesheet.status == 'pending' and timezone.now() > timesheet.deadline_date:
    #         timesheet.tl_approval = True
    #         timesheet.save()
    # except TimeSheets.DoesNotExist:
    #     pass




















# def handle_autoapprove():
#     obj = TimeSheets.objects.all()
#     print('Timesheet get auto approved if deadline date is crossed')
#     obj.approved  = True
#     obj.save()