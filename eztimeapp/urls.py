from django.urls import path, include,re_path
from . import views

from rest_framework import routers
from django.conf.urls.static import static
# from django.conf.urls import url
from eztimeapp.views import *
from .views import *


app_name = 'eztimeapp'

urlpatterns = [

    # all records with pagination 
    # path('all-organization-pagination', OrganizationApiViewAll.as_view()),
    # path('all-clients-pagination', ClientsApiViewAll.as_view()),
    # path('all-industries-pagination', TypeOfIndustriesApiViewAll.as_view()),
    # path('all-orgpeoples-pagination', OrgPeopleGroupViewAll.as_view()),
    # path('all-department-pagination', OrganizationDepartmentViewAll.as_view()),
    # path('all-clientsdms-pagination', ClientsDmsViewAll.as_view()),
    # path('all-organizationCostCenter-pagination', OrganizationCostCentersApiViewAll.as_view()),
    # path('all-clientsOtherContactDetail-pagination', ClientsOtherContactDetailsViewAll.as_view()),
    # path('all-organizationRoles-pagination', OrganizationRolesViewAll.as_view()),
    # path('all-projects-pagination',ProjectsAPIViewAll.as_view()), 
    # path('all-taskprojectcategories-pagination',TaskProjectCategoriesApiViewAll.as_view()), 
    # path('all-projectfiletemplates-pagination',ProjectCategoriesFilesTemplatesApiViewAll.as_view()), 
    # path('all-projectstatusmaincategory-pagination',ProjectStatusMainCategoryApiViewAll.as_view()), 
    # path('all-projecthistory-pagination',ProjectHistoryApiViewAll.as_view()), 
    # path('all-projectstatussubcategory-pagination',ProjectStatusSubCategoryApiViewAll.as_view()),
    # path('all-projectfiles-pagination',ProjectFilesApiViewAll.as_view()),
    # path('all-geozones-pagination',GeoZonesApiViewAll.as_view()),
    # path('all-geotimezones-pagination',GeoTimezonesApiViewAll.as_view()),
    # path('all-geocurrencies-pagination',GeoCurrenciesApiViewAll.as_view()),
    # path('all-geocountries-pagination',GeoCountriesApiViewAll.as_view()),
    # path('all-geostates-pagination',GeoStatesApiViewAll.as_view()),
    # path('all-geocities-pagination',GeoCitiesApiViewAll.as_view()),
    # path('all-geocountriescurrencies-pagination',GeoCountriesCurrenciesApiViewAll.as_view()),
    # path('all-geocontinents-pagination',GeoContinentsApiViewAll.as_view()),
    # path('all-geosubcontinents-pagination',GeoSubContinentsApiViewAll.as_view()),
    # path('all-projectcategories-pagination',ProjectCategoriesViewAll.as_view()),
    # path('all-projectdetails-pagination',ProductDetailsViewAll.as_view()),
    


    path('pin', PinApiVew.as_view()),
    path('holidays', HolidaysapiView.as_view()),

    path('register', RegistrationApiVew.as_view()),
    path('login', LoginView.as_view()),
    path('forgot-password-send-otp', ForgotPasswordSendOtp.as_view()),
    path('otp-verify-forgot-pass', OtpVerificationForgotpass.as_view()),
    path('password-reset', ForgotPasswordReset.as_view()),
    path('change-password', ChangePassword.as_view(), name="ChangePassword"),

    path('notification-center', NotificationCenterApiView.as_view()),
    
    path('manager-review', ManagerReviewApiView.as_view()),
    path('manager-review/<int:pk>', ManagerReviewApiView.as_view()), 

    path('add-on-leave-request', AddOnLeaveRequestApiView.as_view()),
    path('add-on-leave-request/<int:pk>', AddOnLeaveRequestApiView.as_view()), 

    path('user-role', UserRoleApiView.as_view()),
    path('user-role/<int:pk>', UserRoleApiView.as_view()), 

    path('organization', OrganizationApiView.as_view()),
    path('organization/<int:pk>', OrganizationApiView.as_view()),

    path('type-of-industries', TypeOfIndustriesApiView.as_view()),
    path('type-of-industries/<int:pk>', TypeOfIndustriesApiView.as_view()),

    path('clients', ClientsApiView.as_view()),
    path('clients/<int:pk>', ClientsApiView.as_view()),


    path('org-people-group', OrgPeopleGroupView.as_view()),
    path('org-people-group/<int:pk>', OrgPeopleGroupView.as_view()),

    path('organization-department', OrganizationDepartmentView.as_view()),
    path('organization-department/<int:pk>', OrganizationDepartmentView.as_view()),

    path('organization-cost-centers', OrganizationCostCentersView.as_view()),
    path('organization-cost-centers/<int:pk>', OrganizationCostCentersView.as_view()),

    path('organization-roles', OrganizationRolesView.as_view()),
    path('organization-roles/<int:pk>', OrganizationRolesView.as_view()),

    path('clients-dms', ClientsDMS.as_view()),
    path('clients-dms/<int:pk>', ClientsDMS.as_view()),


    path('clients-other-contact-details', ClientsOtherContactDetailsView.as_view()),
    path('clients-other-contact-details/<int:pk>', ClientsOtherContactDetailsView.as_view()),

    path('project-categories', ProjectCategoriesView.as_view()),
    path('project-categories/<int:pk>', ProjectCategoriesView.as_view()),

    
###########################Fara##########################################

    path('projects', ProjectsAPIView.as_view()),
    path('projects/<int:pk>', ProjectsAPIView.as_view()),

    path('task-project-categories', TaskProjectCategoriesApiView.as_view()),
    path('task-project-categories/<int:pk>', TaskProjectCategoriesApiView.as_view()),


    path('project-categories-files-templates', ProjectCategoriesFilesTemplatesApiView.as_view()),
    path('project-categories-files-templates/<int:pk>', ProjectCategoriesFilesTemplatesApiView.as_view()),



    path('project-status-main-category', ProjectStatusMainCategoryApiView.as_view()),
    path('project-status-main-category/<int:pk>', ProjectStatusMainCategoryApiView.as_view()),


    path('project-history', ProjectHistoryApiView.as_view()),
    path('project-history/<int:pk>', ProjectHistoryApiView.as_view()),

    path('project-status-sub-category', ProjectStatusSubCategoryApiView.as_view()),
    path('project-status-sub-category/<int:pk>', ProjectStatusSubCategoryApiView.as_view()),


    path('project-files', ProjectFilesApiView.as_view()),
    path('project-files/<int:pk>', ProjectFilesApiView.as_view()),


    path('geo-zones', GeoZonesApiView.as_view()),
    path('geo-zones/<int:pk>', GeoZonesApiView.as_view()),


    path('geo-time-zones', GeoTimezonesApiView.as_view()),
    path('geo-time-zones/<int:pk>', GeoTimezonesApiView.as_view()),


    path('geo-currencies', GeoCurrenciesApiView.as_view()),
    path('geo-currencies/<int:pk>', GeoCurrenciesApiView.as_view()),


    path('geo-countries', GeoCountriesApiView.as_view()),
    path('geo-countries/<int:pk>', GeoCountriesApiView.as_view()),

    path('geo-states', GeoStatesApiView.as_view()),
    path('geo-states/<int:pk>', GeoStatesApiView.as_view()),


    path('geo-cities', GeoCitiesApiView.as_view()),
    path('geo-cities/<int:pk>', GeoCitiesApiView.as_view()),


    path('geo-countries-currencies', GeoCountriesCurrenciesApiView.as_view()),
    path('geo-countries-currencies/<int:pk>', GeoCountriesCurrenciesApiView.as_view()),

    path('geo-continents', GeoContinentsApiView.as_view()),
    path('geo-continents/<int:pk>', GeoContinentsApiView.as_view()),

    path('geo-sub-continents', GeoSubContinentsApiView.as_view()),
    path('geo-sub-continents/<int:pk>', GeoSubContinentsApiView.as_view()),

#-------
    
    path('product-details', ProductDetailsView.as_view()),
    path('product-details/<int:pk>', ProductDetailsView.as_view()),

    path('organization-leave-type', OrganizationLeaveTypeApiView.as_view()),
    path('organization-leave-type/<int:pk>', OrganizationLeaveTypeApiView.as_view()),

    path('organization-cost-centers', OrganizationCostCentersApiView.as_view()),
    path('organization-cost-centers/<int:pk>', OrganizationCostCentersApiView.as_view()),

    path('organization-cost-centers-leave-type', OrganizationCostCentersLeaveTypeApiView.as_view()),
    path('organization-cost-centers-leave-type/<int:pk>', OrganizationCostCentersLeaveTypeApiView.as_view()),

    path('users-leave-master', UsersLeaveMasterApiView.as_view()),
    path('users-leave-master/<int:pk>', UsersLeaveMasterApiView.as_view()),

    path('organization-cost-centers-year-list', OrganizationCostCentersYearListApiView.as_view()),
    path('organization-cost-centers-year-list/<int:pk>', OrganizationCostCentersYearListApiView.as_view()),

    path('users-leave-applications', UsersLeaveApplicationsApiView.as_view()),
    path('users-leave-applications/<int:pk>', UsersLeaveApplicationsApiView.as_view()),

    path('users-leave-details', leaveDetailsApiView.as_view()),
    path('users-leave-details/<int:pk>', leaveDetailsApiView.as_view()),

    path('user-leaves-allotment-list', UserLeaveAllotmentListApiView.as_view()),
    path('user-leaves-allotment-list/<int:pk>', UserLeaveAllotmentListApiView.as_view()),

    path('user-leave-list', UserLeaveListApiView.as_view()),
    path('user-leave-list/<int:pk>', UserLeaveListApiView.as_view()),

    path('project-categories-checklist', ProjectCategoriesChecklistApiView.as_view()),
    path('project-categories-checklist/<int:pk>', ProjectCategoriesChecklistApiView.as_view()),

    path('task-project-categories-checklist', TaskProjectCategoriesChecklistApiView.as_view()),
    path('task-project-categories-checklist/<int:pk>', TaskProjectCategoriesChecklistApiView.as_view()),

    path('timesheet-master-details', TimesheetMasterDetailsApiView.as_view()),
    path('timesheet-master-details/<int:pk>', TimesheetMasterDetailsApiView.as_view()),

    path('timesheet-master', TimesheetMasterApiView.as_view()),
    path('timesheet-master/<int:pk>', TimesheetMasterApiView.as_view()),

    path('profile-custom-user', UserApiView.as_view()),
    path('profile-custom-user/<int:pk>', UserApiView.as_view()),



    path('prefix-suffix', PrefixSuffixApiView.as_view()),
    path('prefix-suffix/<int:pk>', PrefixSuffixApiView.as_view()),
    

    path('center', CenterApiView.as_view()),
    path('center/<int:pk>', CenterApiView.as_view()),

    path('people', PeopleApiView.as_view()),
    path('people/<int:pk>', PeopleApiView.as_view()),

    path('tag', TagApiView.as_view()),
    path('tag/<int:pk>', TagApiView.as_view()),

    path('time-sheet', TimeSheetApiView.as_view()),
    path('time-sheet/<int:pk>', TimeSheetApiView.as_view()),

    path('master-leave-types', MasterLeaveTypesApiView.as_view()),
    path('master-leave-types/<int:pk>', MasterLeaveTypesApiView.as_view()),

    path('leave-application', leaveApplicationApiView.as_view()),
    path('leave-application/<int:pk>', leaveApplicationApiView.as_view()),

    path('leave-application-state-change', leaveApplicationStateChangeApiView.as_view()),
    path('leave-application-state-change/<int:pk>', leaveApplicationStateChangeApiView.as_view()),

    path('emp-balance-leave', BalanceApiView.as_view()),
    path('emp-balance-leave/<int:pk>', BalanceApiView.as_view()),

    path('profile', ProfileApiView.as_view()),
    path('profile/<int:pk>', ProfileApiView.as_view()),

    path('dash-board', DashBoardview.as_view()),
    path('dash-board/<int:pk>', DashBoardview.as_view()),
    
    path('subscriptionplan', SubscriptionPlanAPIView.as_view()),
    path('subscription_lan/<int:pk>', SubscriptionPlanAPIView.as_view()), 

    # OFFICE working days
    path('office-working-days', OfficeWorkingDaysApiView.as_view()),
    path('office-working-days/<int:pk>', OfficeWorkingDaysApiView.as_view()), 

    # 3rd party
    path('country-state-city', CountryStateCityApiView.as_view()),
    path('country-state-city/<int:pk>', CountryStateCityApiView.as_view()), 


    
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

