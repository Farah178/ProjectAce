from django.urls import path
from m1.views import *

urlpatterns = [
    path('timespent/', TimespentAPIView.as_view()),
    # path('all-time-sheets/', TimeSheetApiViewAll.as_view()),

    # Time Sheet
    path('time-sheets', TimesheetApiViews.as_view()),
    path('time-sheets/<int:pk>', TimesheetApiViews.as_view()),

    path('time-sheets-calender', TimesheetcalenderAPIView.as_view()),

    path('time-sheets-status-update', UpdateTimesheetStatus.as_view()),

    # TODAYS APPROVAL Timesheet
    path('time-sheets-todays-approval', TodayapprovalTimesheetAPIView.as_view()),
    path('time-sheets-todays-approval/<int:pk>', TodayapprovalTimesheetAPIView.as_view()),

    # MONTHLY Timesheet
    path('time-sheets-monthly', MonthlyTimeSheetAPIView.as_view()),
    path('time-sheets-monthly/<int:pk>', MonthlyTimeSheetAPIView.as_view()),

    # APPROVAL Timesheet CONFIGERATION    
    path('time-sheets-approval-config', ApprovalTimesheetAPIView.as_view()),
    path('time-sheets-approval-config/<int:pk>', ApprovalTimesheetAPIView.as_view()),


    # HOLD
    path('time-sheets-deadline-crossed', DeadLineCrossedTimesheetAPIView.as_view()),
    path('time-sheets-deadline-crossed/<int:pk>', DeadLineCrossedTimesheetAPIView.as_view()),

    # Projects and TASK
    path('project-info', ProjectbyClient.as_view()),
    path('project-task-info',TaskbyProjects.as_view()),


    path('filter-by-user', UpdateTimesheetStatus.as_view()),
    
    path('get-time-stamp-values', GetValuesForAddTimeStamp.as_view()),
    path('get_employee_list/', ManageremployeelistTimesheetAPIView.as_view()),    

    # path('timesheet-approval-config/', TimesheetApprovalConfigAPIView.as_view()),

]   
