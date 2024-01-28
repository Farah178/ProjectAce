from django.contrib import admin
from .models import *
from import_export.admin import ImportExportModelAdmin

# Register your models here.
model_list = [

    
    Clients,
    
    OrgPeopleGroup,
    ProjectCategories,

    
    TaskProjectCategoriesChecklist,
    ProjectCategoriesFilesTemplates,
    
    ProjectHistory,
    
    ProjectFiles,
    GeoZones,
    GeoTimezones,
    GeoCurrencies,
    GeoCountries,
    GeoStates,
    GeoCities,
    GeoCountriesCurrencies,
    GeoContinents,
    GeoSubContinents,
    
    OrganizationCostCenters,
    ClientsDms,
    ClientsOtherContactDetails,
    OrganizationRoles,
    SubscriptionPlan,
    
    OfficeWorkingDays,
    

]    
admin.site.register(model_list)   
@admin.register(NotificationCenter)
class NotificationCenterAdmin(admin.ModelAdmin):
    list_display = ("id","project_id",
                        "notify",
                        "info")

@admin.register(TypeOfIndustries)
class TypeOfIndustriesAdmin(admin.ModelAdmin):
    list_display = ("id","org_ref_id",
                        "toi_title",
                        "toi_description",
                        "toi_status",
                        "toi_type",
                        "sort")

@admin.register(ProjectStatusSubCategory)
class ProjectStatusSubCategoryAdmin(admin.ModelAdmin):
    list_display = ("id","pssc_name",
                        "pssc_status",
                        "sort")

@admin.register(ProjectStatusMainCategory)
class ProjectStatusMainCategoryAdmin(admin.ModelAdmin):
    list_display = ("id","psmc_name",
                        "psmc_status",
                        "psmc_color_code",
                        "sort")

@admin.register(PrefixSuffix)
class PrefixSuffixAdmin(admin.ModelAdmin):
    list_display = ("id","prefix",
                        "suffix",
                        "prefixsuffix_status",
                        "added_date",
                        "sort")

@admin.register(Center)
class CenterAdmin(admin.ModelAdmin):
    list_display = ("id","center_name",
                        "year_start_date",
                        "year_end_date",
                        "center_status",
                        "sort")




@admin.register(OrganizationDepartment)
class OrganizationDepartmentAdmin(admin.ModelAdmin):
    list_display = ("id","org_ref_id",
                        "od_added_by_ref_user_id",
                        "od_name",
                        "od_status",
                        "od_c_date",
                        "od_m_date",
                        "sort")

@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ("id","tag_name","added_date","tage_status")

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("id","conctact_person_email","org_email","org_name")

@admin.register(TaskProjectCategories)
class TaskProjectCategoriesAdmin(admin.ModelAdmin):
    list_display = ("id",
                "tpc_name",
                "task_name",
                "tpc_status",
                "tpc_list",
                "task_list",
                "file_templates_list",
                "pc_ref_id",
                "p_ref_id",
                "org_ref_id",)


@admin.register(Projects)
class ProjectsAdmin(admin.ModelAdmin):
    list_display = ("id", "p_name",
        "people_ref_list",
        "p_people_type",
        "task_project_category_list",
        "project_related_task_list",
        "org_ref_id",
        "user_ref_id",
        "c_ref_id",)


@admin.register(leaveApplication)
class leaveApplicationAdmin(admin.ModelAdmin):
    list_display = ("id","cc_to" ,"user_id", "leave_type_id","days","balance")

@admin.register(MasterLeaveTypes)
class MasterLeaveTypesAdmin(admin.ModelAdmin):
    list_display = ("id", "leave_applicable_for_id","leave_title","no_of_leaves","carry_forward_per",
"gracefull_days",
"max_encashments",
"yearly_leaves",
"monthly_leaves")

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ("id","organization_id","user_role_id", "super_user_ref_id","center_id","u_email")
    # list_editable = ("center_id",)

@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ("user_role_name", "module_name", "permissions","description","priority","role_status")

@admin.register(People)
class PeopleAdmin(admin.ModelAdmin):
    list_display = ("id", 
    "user",
"user_reporting_manager_ref",
"organization",
"department",
"role",
"cost_center",
"tags",
"sort",)
    # list_editable = ("center_id",)

# @admin.register(Account)
# class AccountAdmin(ImportExportModelAdmin):
#     list_display = ('industry','business_type','account_type','account_name','description')
