from django.db import models
from eztimeapp.models import *
# Create your models here.
class Timespent(models.Model):
    name = models.CharField(max_length=250, blank=True, null=True)
    created_date_time= models.DateTimeField(auto_now_add=True, null=True)
    updated_date_time = models.DateTimeField(auto_now_add=False, null=True)

    def __str__(self):
        return self.name


class TimeSheets(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    client =  models.ForeignKey(Clients, on_delete=models.CASCADE, blank=True, null=True, related_name='tm_clent')
    project=  models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True, related_name="tm_project")
    project_category =  models.JSONField(blank=True, null=True)
    time_spent = models.CharField(max_length=250, blank=True, null=True)
    description=  models.CharField(max_length=250, blank=True, null=True)
    
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True, related_name="created_by")
    reporting_manager_ref= models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='reporting_managerref', blank=True, null=True)
    task_worked_list =  models.JSONField(blank=True, null=True)
    approved_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    approved_state =  models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)
    applied_date  =  models.CharField(max_length=250, blank=True, null=True)
    applied_date_timestamp =  models.CharField(max_length=250, blank=True, null=True)
    approved_date_timestamp =  models.CharField(max_length=250, blank=True, null=True)
    approved_date =  models.CharField(max_length=250, blank=True, null=True)
    approved_date_time = models.DateTimeField(auto_now_add=False, null=True)

    created_date_time= models.DateTimeField(auto_now_add=True, null=True)
    
    # def __str__(self):
    #     return self.time_spent
    
#Create your models here.

class TimesheetsApprovalConfig(models.Model):
    approved_by_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True, related_name="timesheet_approved_by_user")
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)

    approval_period = models.CharField(max_length=250, blank=True, null=True)
    approval_period_in_days = models.CharField(max_length=250, blank=True, null=True)
    grace_days_to_approve = models.CharField(max_length=250, blank=True, null=True)
    auto_approve = models.BooleanField(default=False)
    active_status = models.CharField(max_length=250, blank=True, null=True)

    created_date_time= models.DateTimeField(auto_now_add=True, null=True)
    approved_date_time = models.DateTimeField(auto_now_add=False, null=True)

#Create your models here.
class TodaysApproval(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    s_no = models.IntegerField()
    date = models.DateField(blank=True, null=True)
    people = models.ForeignKey(People, on_delete=models.CASCADE, null=True, blank=True)
    timesheets = models.ForeignKey(TimeSheets, on_delete=models.CASCADE, null=True, blank=True)
    created_date_time = models.DateTimeField(auto_now_add=True, null=True) 
    saved_on = models.CharField(max_length=250, blank=True, null=True)
    approved_status = models.CharField(max_length=250, blank=True, null=True)
    action = models.CharField(max_length=250, blank=True, null=True)
















