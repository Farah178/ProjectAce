from django.contrib import admin
from .models import *
from import_export.admin import ImportExportModelAdmin

# Register your models here.


model_list = [
Timespent,

TimesheetsApprovalConfig,
TodaysApproval,
]    
admin.site.register(model_list)   


# @admin.register(Timespent)
# class Timespent(admin.ModelAdmin):
#     list_display = ['id','name','created_date_time','updated_date_time']
    
@admin.register(TimeSheets)
class TimeSheet(admin.ModelAdmin):
    list_display = ["id","created_by_id","approved_by_id","reporting_manager_ref_id","approved_state","task_worked_list","time_spent",
"description","client_id",
"project_id",
"project_category","applied_date","applied_date_timestamp","approved_date_time","approved_date_timestamp"]

       


# @admin.register(TimesheetsApprovalConfig)
# class TimesheetsApprovalConfig(admin.ModelAdmin):
#     list_display = ['id','approval_period','days_to_approve','auto_approve','active_status','approved_by_user','created_date_time','approved_date_time']


# @admin.register(TodaysApproval)
# class TodaysApproval(admin.ModelAdmin):
#     list_display = ['id','s_no','date','people','created_date_time','saved_on','approved_status','action']