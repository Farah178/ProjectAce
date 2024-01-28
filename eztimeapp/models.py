from ctypes import addressof
import email
from sre_constants import SRE_FLAG_TEMPLATE
# from sre_parse import State
from statistics import mode
from sys import dont_write_bytecode
from types import CoroutineType
from unicodedata import name
from django.db import models
from django.contrib.auth.models import User
from django.db.models.fields import CommaSeparatedIntegerField




class Organization(models.Model):
    # user_ref                         = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    org_qr_uniq_id                   = models.CharField(max_length=100, null=True, blank=True)
    org_name                         = models.CharField(max_length=100, null=True, blank=True)
    org_email                        = models.CharField(max_length=100, null=True, blank=True)
    org_phone                        = models.CharField(max_length=100, null=True, blank=True)
    org_mobile                       = models.CharField(max_length=100, null=True, blank=True)
    org_fax                          = models.CharField(max_length=100, null=True, blank=True)
    org_website                      = models.CharField(max_length=100, null=True, blank=True)
    org_address                      = models.CharField(max_length=100, null=True, blank=True)
    org_city                         = models.CharField(max_length=100, null=True, blank=True)
    org_state                        = models.CharField(max_length=100, null=True, blank=True)
    org_country                      = models.CharField(max_length=100, null=True, blank=True)
    org_postal_code                  = models.CharField(max_length=100, null=True, blank=True)
    org_profile_updated_status       = models.CharField(max_length=100, null=True, blank=True)
    org_default_currency_type        = models.CharField(max_length=100, null=True, blank=True)
    org_default_timezone             = models.CharField(max_length=100, null=True, blank=True)
    org_status                       = models.CharField(max_length=100, null=True, blank=True)
    org_subscription_plan            = models.CharField(max_length=100, null=True, blank=True)
    org_logo                         = models.CharField(max_length=100, null=True, blank=True)
    org_logo_path                    = models.CharField(max_length=100, null=True, blank=True)
    base64                           = models.TextField(max_length=50000, null=True, blank=True)   
    opg_c_timestamp                  = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    opg_m_timestamp                  = models.DateTimeField(auto_now=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)


    conctact_person_designation   = models.CharField(max_length=100, null=True, blank=True)
    conctact_person_name   = models.CharField(max_length=100, null=True, blank=True)
    conctact_person_email   = models.CharField(max_length=100, null=True, blank=True)
    conctact_person_password = models.CharField(max_length=100, null=True, blank=True)
    conctact_person_phone_number   = models.CharField(max_length=100, null=True, blank=True)
    sort =  models.IntegerField( blank=True, null=True)

class UserRole(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    user_role_name =  models.CharField(max_length=250, blank=True, null=True)
    description =  models.CharField(max_length=250, blank=True, null=True)
    priority =  models.CharField(max_length=250, blank=True, null=True)
    role_status = models.CharField(max_length=250, blank=True, null=True)

    module_name =  models.JSONField(blank=True, null=True)
    permissions =  models.JSONField(blank=True, null=True)


    created_time = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    updated_time = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)


class Center(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    center_name  =  models.CharField(max_length=250, blank=True, null=True)
    year_start_date=  models.CharField(max_length=250, blank=True, null=True)
    year_end_date=  models.CharField(max_length=250, blank=True, null=True)
    center_status =  models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)

    sort =  models.IntegerField( blank=True, null=True)

class CustomUser(models.Model):
    super_user_ref = models.ForeignKey(User, on_delete=models.CASCADE,related_name='user_created_by', blank=True, null=True)
    center   = models.ForeignKey(Center, on_delete=models.SET_NULL,related_name='CustomCenter', blank=True, null=True)
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE,related_name='UserRole', blank=True, null=True) 
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    

    u_unique_id                  = models.CharField(max_length=100, null=True, blank=True)
    u_org_code                   = models.CharField(max_length=100, null=True, blank=True)
    u_first_name                 = models.CharField(max_length=100, null=True, blank=True)
    u_last_name                  = models.CharField(max_length=100, null=True, blank=True)
    u_gender                     = models.CharField(max_length=100, null=True, blank=True)
    u_marital_status             = models.CharField(max_length=100, null=True, blank=True)
    u_designation                = models.CharField(max_length=100, null=True, blank=True)
    u_date_of_joining            = models.CharField(max_length=100, null=True, blank=True)
    u_profile_photo              = models.CharField(max_length=100, null=True, blank=True)
    u_profile_path               = models.CharField(max_length=100, null=True, blank=True)
    u_profile_base_url           = models.CharField(max_length=100, null=True, blank=True)
    u_email                      = models.CharField(max_length=100, null=True, blank=True)
    u_phone_no                   = models.CharField(max_length=100, null=True, blank=True)
    u_password                   = models.CharField(max_length=100, null=True, blank=True)
    u_status                     = models.CharField(max_length=100, null=True, blank=True)
    u_created_from               = models.CharField(max_length=100, null=True, blank=True)
    u_reset_otp                  = models.CharField(max_length=100, null=True, blank=True)
    u_last_login                 = models.CharField(max_length=100, null=True, blank=True)
    u_login_token_key            = models.CharField(max_length=100, null=True, blank=True)
    u_activation_status          = models.CharField(max_length=100, null=True, blank=True)
    u_profile_updated_status     = models.CharField(max_length=100, null=True, blank=True)
    u_activation_link_sent_count = models.CharField(max_length=100, null=True, blank=True)
    u_activation_link            = models.CharField(max_length=100, null=True, blank=True)
    u_acc_expiry_date            = models.CharField(max_length=100, null=True, blank=True)
    u_is_first_user              = models.CharField(max_length=100, null=True, blank=True)
    u_country                    = models.CharField(max_length=100, null=True, blank=True)
    u_state                      = models.CharField(max_length=100, null=True, blank=True)
    u_city                       = models.CharField(max_length=100, null=True, blank=True)
    u_address                    = models.CharField(max_length=100, null=True, blank=True)
    u_postal_code                = models.CharField(max_length=100, null=True, blank=True)
    u_dob                        = models.CharField(max_length=100, null=True, blank=True)
    u_screen_lock_status         = models.CharField(max_length=100, null=True, blank=True)
    tags                         = models.CharField(max_length=100, null=True, blank=True)

    u_c_timestamp                = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    u_m_timestamp                = models.DateTimeField(auto_now=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    

class TypeOfIndustries(models.Model):
    org_ref         = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    toi_c_date      = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    toi_m_dat       = models.DateTimeField(auto_now=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    toi_title       = models.CharField(max_length=100, null=True, blank=True)
    toi_description = models.CharField(max_length=100, null=True, blank=True)
    toi_status      = models.CharField(max_length=100, null=True, blank=True)
    toi_type        = models.CharField(max_length=100, null=True, blank=True)
    
    sort =  models.IntegerField( blank=True, null=True)

class Clients(models.Model):
    org_ref                     = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    user_ref                    = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    toi_ref                     = models.ForeignKey(TypeOfIndustries, on_delete=models.CASCADE, blank=True, null=True)
    c_name                      = models.CharField(max_length=100, null=True, blank=True)
    c_code                      = models.CharField(max_length=100, null=True, blank=True)
    c_address                   = models.CharField(max_length=100, null=True, blank=True)
    c_type                      = models.CharField(max_length=100, null=True, blank=True)
    c_contact_person            = models.CharField(max_length=100, null=True, blank=True)
    c_contact_person_email_id   = models.CharField(max_length=100, null=True, blank=True)
    c_contact_person_phone_no   = models.CharField(max_length=100, null=True, blank=True)
    c_satus                     = models.CharField(max_length=100, null=True, blank=True)
    c_c_timestamp               = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    c_m_timestamp               = models.DateTimeField(auto_now=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    project  = models.CharField(max_length=100, null=True, blank=True)
    sort =  models.IntegerField( blank=True, null=True)

    def __str__(self):
        return self.c_name

class OrgPeopleGroup(models.Model):
    user_ref         = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    org_ref          = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    opg_group_name   = models.CharField(max_length=100, null=True, blank=True)
    opg_status       = models.CharField(max_length=100, null=True, blank=True)
    # opg_ref_org_id = models.CharField(max_length=100, null=True, blank=True)
    opg_c_timestamp  = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    opg_m_timestamp  = models.DateTimeField(auto_now=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class ProjectCategories(models.Model):
    org_ref                     =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    pc_added_by_ref_user        =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    pc_name                     =  models.CharField(max_length=250, blank=True, null=True)
    pc_status                   =  models.CharField(max_length=250, blank=True, null=True)
    pc_c_date                   =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    pc_m_date                   =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    base64 = models.TextField(max_length=250, blank=True, null=True)
    file_attachment= models.FileField(upload_to='file_attachment',max_length=250, blank=True, null=True)
    file_attachment_path= models.CharField(max_length=250, blank=True, null=True)
    file_attachment_name= models.CharField(max_length=250, blank=True, null=True)
    task_name= models.CharField(max_length=250, blank=True, null=True)
    billable_type= models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)
  

class Projects(models.Model):
    org_ref                         = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    user_ref                        = models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='user_ref', blank=True, null=True)
    c_ref                           = models.ForeignKey(Clients, on_delete=models.CASCADE, blank=True, null=True)
    people_ref_list =  models.JSONField(blank=True, null=True)
    # people_ref                      = models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='people_ref', blank=True, null=True)
    opg_ref                         = models.ForeignKey(OrgPeopleGroup, on_delete=models.CASCADE, blank=True, null=True)
    reporting_manager_ref           = models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='reporting_manager_ref', blank=True, null=True)
    approve_manager_ref             = models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='approve_manager_ref', blank=True, null=True)
    pc_ref                          = models.ForeignKey(ProjectCategories, on_delete=models.CASCADE, blank=True, null=True)
    p_description                   = models.CharField(max_length=250, blank=True, null=True)
    p_code                          = models.CharField(max_length=250, blank=True, null=True)
    p_name                          = models.CharField(max_length=250, blank=True, null=True)
    p_people_type                   = models.CharField(max_length=250, blank=True, null=True)
    p_start_date                    = models.CharField(max_length=250, blank=True, null=True)
    p_closure_date                  = models.CharField(max_length=250, blank=True, null=True)
    p_estimated_hours               = models.CharField(max_length=250, blank=True, null=True)
    p_estimated_cost                = models.CharField(max_length=250, blank=True, null=True)
    p_task_checklist_status         = models.CharField(max_length=250, blank=True, null=True)
    p_status                        = models.CharField(max_length=250, blank=True, null=True)
    p_activation_status             = models.CharField(max_length=250, blank=True, null=True)
    task_project_category_list      =  models.JSONField(blank=True, null=True)
    project_related_task_list       =  models.JSONField(blank=True, null=True)
    p_c_date                        = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    p_m_date                        = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class TaskProjectCategories(models.Model):
    pc_ref                              = models.ForeignKey(ProjectCategories , on_delete=models.CASCADE, blank=True, null=True)
    p_ref                               = models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True)
    org_ref                             = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    tpc_added_by_ref_user               = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    
    tpc_name    = models.CharField(max_length=50, blank=True, null=True)
    task_name   =  models.CharField(max_length=250, blank=True, null=True)
    tpc_status  = models.CharField(max_length=50, blank=True, null=True)

    tpc_list =  models.JSONField(blank=True, null=True)
    task_list =  models.JSONField(blank=True, null=True)
    file_templates_list = models.JSONField(blank=True, null=True)
    tpc_c_date                          = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    tpc_m_date                          = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)

    sort =  models.IntegerField( blank=True, null=True)

    # file_attachment_path  =  models.CharField(max_length=250, blank=True, null=True)
    # file_attachment      =  models.CharField(max_length=250, blank=True, null=True)
    # base64=  models.TextField(max_length=50000, blank=True, null=True)
    # billable_type =  models.CharField(max_length=250, blank=True, null=True)
    


class   ProjectCategoriesFilesTemplates(models.Model):
    org_ref                         = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    pcft_added_by_ref_user          = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    ref_pc                          = models.ForeignKey(ProjectCategories, on_delete=models.CASCADE, blank=True, null=True)
    pcft_name                       = models.CharField(max_length=250, blank=True, null=True)
    pcft_filename                   = models.CharField(max_length=250, blank=True, null=True)
    pcft_file_path                  = models.FileField(upload_to='pcft_file_path',max_length=2500, blank=True, null=True)
    pcft_file_base_url              = models.CharField(max_length=200)
    pcft_status                     = models.CharField(max_length=250, blank=True, null=True)
    pcft_c_date                     = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    pcft_m_date                     = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class ProjectStatusMainCategory(models.Model):
    organization                =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    psmc_name                   =  models.CharField(max_length=250, blank=True, null=True)
    psmc_status                 =  models.CharField(max_length=250, blank=True, null=True)
    psmc_color_code             =  models.CharField(max_length=250, blank=True, null=True)
    psmc_c_date                 =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    psmc_m_date                 =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

    


class ProjectHistory(models.Model):
    p_ref                          =  models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True)
    org_ref                        =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    ph_people_ref_user             =  models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='ph_people_ref_user', blank=True, null=True)
    ph_added_by_ref_user           =  models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='ph_added_by_ref_user', blank=True, null=True)
    c_ref                          =  models.ForeignKey(Clients, on_delete=models.CASCADE, blank=True, null=True)
    opg_ref                        =  models.ForeignKey(OrgPeopleGroup, on_delete=models.CASCADE, blank=True, null=True)
    ph_reporting_manager_ref_user  =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='ph_reporting_manager_ref_user',blank=True, null=True)
    ph_approve_manager_ref_user    =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='ph_approve_manager_ref_user',blank=True, null=True)
    pc_ref                         =  models.ForeignKey(ProjectCategories, on_delete=models.CASCADE, blank=True, null=True)
    ph_code                        =  models.CharField(max_length=250, blank=True, null=True)  
    ph_name                        =  models.CharField(max_length=250, blank=True, null=True)
    ph_people_type                 =  models.CharField(max_length=250, blank=True, null=True)
    ph_description                 =  models.CharField(max_length=250, blank=True, null=True)
    ph_start_date                  =  models.DateTimeField(auto_now_add=True,verbose_name="ph_start_date", blank=True, null=True)
    ph_closure_date                =  models.DateTimeField(auto_now_add=True,verbose_name="ph_closure_date", blank=True, null=True)
    ph_estimated_hours             =  models.DateTimeField(auto_now_add=True,verbose_name="ph_estimated_hours", blank=True, null=True)
    ph_estimated_cost              =  models.CharField(max_length=250, blank=True, null=True)
    ph_task_checklist_status       =  models.CharField(max_length=250, blank=True, null=True)
    ph_status                      =  models.CharField(max_length=250, blank=True, null=True)
    ph_activation_status           =  models.CharField(max_length=250, blank=True, null=True)
    ph_c_date                      =  models.DateTimeField(max_length=250,auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    ph_m_date                      =  models.DateTimeField(max_length=250,auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class ProjectStatusSubCategory(models.Model):
    psmc_ref                    =  models.ForeignKey(ProjectStatusMainCategory, on_delete=models.CASCADE, blank=True, null=True)           
    org_ref                     =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    pssc_added_by_ref_user      =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    pssc_name                   =  models.CharField(max_length=250, blank=True, null=True)
    pssc_status                 =  models.CharField(max_length=250, blank=True, null=True)
    pssc_c_date                 =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    pssc_m_date                 =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    color = models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)

class ProjectFiles(models.Model):
    org_ref                     =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    pf_added_ref_user           =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    p_ref                       =  models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True)
    pf_filename                 =  models.CharField(max_length=250, blank=True, null=True)
    pf_file_path                =  models.FileField(upload_to='pf_file_path',max_length=2500)
    pf_base_url                 =  models.CharField(max_length=200)
    pf_status                   =  models.CharField(max_length=250, blank=True, null=True)
    pf_c_date                   =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    pf_m_date                   =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

#added timestamp
class GeoZones(models.Model):
    gz_country_code             =  models.CharField(max_length=250, blank=True, null=True)
    gz_zone_name                =  models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

#added timestamp
class GeoTimezones(models.Model):
    gz_ref                      =  models.ForeignKey(GeoZones, on_delete=models.CASCADE, blank=True, null=True)
    gtm_abbreviation            =  models.CharField(max_length=250, blank=True, null=True)
    gtm_time_start              =  models.DateTimeField(auto_now_add=True,verbose_name="gtm_time_start")
    gtm_gmt_offset              =  models.CharField(max_length=250, blank=True, null=True)
    gtm_dst                     =  models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class GeoCurrencies(models.Model):
    geo_cur_code                =  models.CharField(max_length=250, blank=True, null=True)
    geo_cur_name                =  models.CharField(max_length=250, blank=True, null=True)
    geo_cur_major_name          =  models.CharField(max_length=250, blank=True, null=True)
    geo_cur_major_symbol        =  models.CharField(max_length=250, blank=True, null=True)
    geo_cur_minor_name          =  models.CharField(max_length=250, blank=True, null=True)
    geo_cur_minor_symbol        =  models.CharField(max_length=250, blank=True, null=True)
    geo_cur_minor_value         =  models.CharField(max_length=250, blank=True, null=True)
    geo_cur_c_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    geo_cur_m_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class GeoCountries(models.Model):
    gcounty_name                =  models.CharField(max_length=250, blank=True, null=True)           
    gcounty_cca2                =  models.CharField(max_length=250, blank=True, null=True)
    gcounty_cca3                =  models.CharField(max_length=250, blank=True, null=True)
    gcounty_ccn3                =  models.CharField(max_length=250, blank=True, null=True)
    # gc_ref                      = models.ForeignKey(GeoCurrencies, on_delete=models.CASCADE, blank=True, null=True)
    # gs_ref                      = models.ForeignKey(GeoStates, on_delete=models.CASCADE, blank=True, null=True)
    gcounty_status              =  models.CharField(max_length=250, blank=True, null=True)
    gcounty_c_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    gcounty_m_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class GeoStates(models.Model):
    gcountry_ref                =  models.ForeignKey(GeoCountries, on_delete=models.CASCADE, blank=True, null=True)
    gstate_name                 =  models.CharField(max_length=250, blank=True, null=True)
    gstate_hasc                 =  models.CharField(max_length=250, blank=True, null=True)
    gstate_c_date               =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    gstate_m_date               =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class GeoCities(models.Model):
    ref_gcounty                 = models.ForeignKey(GeoCountries, on_delete=models.CASCADE, blank=True, null=True)       
    gstate_ref                  = models.ForeignKey(GeoStates, on_delete=models.CASCADE, blank=True, null=True)
    zone_ref                    = models.ForeignKey(GeoZones, on_delete=models.CASCADE, blank=True, null=True)
    gcity_name                  = models.CharField(max_length=250, blank=True, null=True) 
    gcity_latitude              = models.CharField(max_length=250, blank=True, null=True)
    gcity_longitude             = models.CharField(max_length=250, blank=True, null=True)
    gcity_c_date                = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    gcity_m_date                = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

#added timestamp
class GeoCountriesCurrencies(models.Model):
    gcounty_ref   = models.ForeignKey(GeoCountries, on_delete=models.CASCADE, blank=True, null=True) 
    geo_cur_ref   = models.ForeignKey(GeoCurrencies, on_delete=models.CASCADE, blank=True, null=True) 
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class GeoContinents(models.Model):
    gc_name                 =  models.CharField(max_length=250, blank=True, null=True)
    gc_c_date               =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    gc_m_date               =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class GeoSubContinents(models.Model):
    gsc_name                =  models.CharField(max_length=250, blank=True, null=True)
    gc_ref                  =  models.ForeignKey(GeoCurrencies, on_delete=models.CASCADE, blank=True, null=True) 
    gsc_c_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    gsc_m_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class OrganizationDepartment(models.Model):
    org_ref                 =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    od_added_by_ref_user    =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    od_name                 =  models.CharField(max_length=250, blank=True, null=True)
    od_status               =  models.CharField(max_length=250, blank=True, null=True)
    od_c_date               =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    od_m_date               =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

# class OrganizationCostCenters(models.Model):
#     org_ref                 =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
#     occ_added_by_ref_user   =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
#     occ_cost_center_name    =  models.CharField(max_length=250, blank=True, null=True)
#     occ_leave_mgmt_status   =  models.CharField(max_length=250, blank=True, null=True)
#     occ_currency_type       =  models.CharField(max_length=250, blank=True, null=True)
#     occ_status              =  models.CharField(max_length=250, blank=True, null=True)
#     occ_c_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
#     occ_m_date              =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
#     sort =  models.IntegerField( blank=True, null=True)

class ClientsDms(models.Model):
    ref_org                 =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    cdms_added_ref_user     =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    c_ref                   =  models.ForeignKey(Clients, on_delete=models.CASCADE, blank=True, null=True)
    cdms_filename           =  models.CharField(max_length=250, blank=True, null=True)    
    cdms_file_path          =  models.CharField(max_length=250, blank=True, null=True)
    cdms_base_url           =  models.CharField(max_length=250, blank=True, null=True)
    cdms_file_ref_name      =  models.CharField(max_length=250, blank=True, null=True)
    cdms_status             =  models.CharField(max_length=250, blank=True, null=True)
    cdms_c_date             =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)    
    cdms_m_date             =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)


class ClientsOtherContactDetails(models.Model):
    c_ref                       =  models.ForeignKey(Clients, on_delete=models.CASCADE, blank=True, null=True)
    org_ref                     =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    cocd_added_by_ref_user      =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    cocd_name                   =  models.CharField(max_length=250, blank=True, null=True)
    cocd_phone                  =  models.CharField(max_length=250, blank=True, null=True)
    cocd_email                  =  models.CharField(max_length=250, blank=True, null=True)
    cocd_satus                  =  models.CharField(max_length=250, blank=True, null=True)       
    cocd_c_date                 =  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True) 
    cocd_m_date                 =  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)


class OrganizationRoles(models.Model):
    org_ref                     =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    or_added_by_ref_user        =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    or_name                     =  models.CharField(max_length=250,  blank=True, null=True)
    or_description              =  models.CharField(max_length=250, blank=True, null=True)  
    or_priority                 =  models.CharField(max_length=250, blank=True, null=True)
    or_status                   =  models.CharField(max_length=250, blank=True, null=True)
    or_type                     =  models.CharField(max_length=250, blank=True, null=True)
    or_permission               =  models.CharField(max_length=250, blank=True, null=True)
    or_c_date                   =  models.CharField(max_length=250, blank=True, null=True)
    or_m_date                   =  models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)

    
#------------------------------------
class ProductDetails(models.Model):
    pd_app_name=  models.CharField(max_length=250, blank=True, null=True)
    pd_app_tag_line=  models.CharField(max_length=250, blank=True, null=True)
    pd_company_name=  models.CharField(max_length=250, blank=True, null=True)
    pd_company_address=  models.CharField(max_length=250, blank=True, null=True)
    pd_company_email_id=  models.CharField(max_length=250, blank=True, null=True)
    pd_company_phone_no=  models.CharField(max_length=250, blank=True, null=True)
    pd_web_version=  models.CharField(max_length=250, blank=True, null=True)
    pd_poweredbyweblink=  models.CharField(max_length=250, blank=True, null=True)
    pd_facebook_link=  models.CharField(max_length=250, blank=True, null=True)
    pd_twitter_link=  models.CharField(max_length=250, blank=True, null=True)
    pd_linkedin_link=  models.CharField(max_length=250, blank=True, null=True)
    pd_product_logo=  models.CharField(max_length=250, blank=True, null=True)
    pd_product_logo_base_url=  models.CharField(max_length=250, blank=True, null=True)
    pd_product_logo_path=  models.CharField(max_length=250, blank=True, null=True)
    pd_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    pd_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    pd_status=  models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)

class  OrganizationLeaveType(models.Model):
    org_reff=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    olt_added_by_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    #do check this id
    olt_ref_occ_id_list=  models.CharField(max_length=250, blank=True, null=True)
    olt_name=  models.CharField(max_length=250, blank=True, null=True)
    olt_description=  models.CharField(max_length=250, blank=True, null=True)
    olt_status=  models.CharField(max_length=250, blank=True, null=True)
    olt_no_of_leaves=  models.CharField(max_length=250, blank=True, null=True)
    olt_no_of_leaves_yearly=  models.CharField(max_length=250, blank=True, null=True)
    olt_no_of_leaves_monthly=  models.CharField(max_length=250, blank=True, null=True)
    olt_accrude_monthly_status=  models.CharField(max_length=250, blank=True, null=True)
    olt_carry_forward=  models.CharField(max_length=250, blank=True, null=True)
    olt_applicable_for=  models.CharField(max_length=250, blank=True, null=True)
    olt_people_applicable_for=  models.CharField(max_length=250, blank=True, null=True)
    olt_gracefull_status=  models.CharField(max_length=250, blank=True, null=True)
    olt_gracefull_days=  models.CharField(max_length=250, blank=True, null=True)
    olt_enchashment_status=  models.CharField(max_length=250, blank=True, null=True)
    olt_max_enchashment_leaves=  models.CharField(max_length=250, blank=True, null=True)
    olt_editable=  models.CharField(max_length=250, blank=True, null=True)
    olt_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    olt_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class OrganizationCostCenters(models.Model):
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    occ_added_by_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    occ_cost_center_name=  models.CharField(max_length=250, blank=True, null=True)
    occ_leave_mgmt_status=  models.CharField(max_length=250, blank=True, null=True)
    occ_currency_type=  models.CharField(max_length=250, blank=True, null=True)
    occ_status=  models.CharField(max_length=250, blank=True, null=True)
    occ_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    occ_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class OrganizationCostCentersLeaveType(models.Model):
    olt_ref=  models.ForeignKey(OrganizationLeaveType, on_delete=models.CASCADE, blank=True, null=True)
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    occ_ref=  models.ForeignKey(OrganizationCostCenters, on_delete=models.CASCADE, blank=True, null=True)
    occl_added_by_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,related_name='occl_added_by_ref_user')
    occl_name=  models.CharField(max_length=250, blank=True, null=True)
    occl_description=  models.CharField(max_length=250, blank=True, null=True)
    occl_status=  models.CharField(max_length=250, blank=True, null=True)
    occl_alloted_leaves=  models.CharField(max_length=250, blank=True, null=True)
    occl_alloted_leaves_yearly=  models.CharField(max_length=250, blank=True, null=True)
    occl_alloted_leaves_monthly=  models.CharField(max_length=250, blank=True, null=True)
    occl_accrude_monthly_status=  models.CharField(max_length=250, blank=True, null=True)
    occl_carry_forward=  models.CharField(max_length=250, blank=True, null=True)
    occl_gracefull_status=  models.CharField(max_length=250, blank=True, null=True)
    occl_gracefull_days=  models.CharField(max_length=250, blank=True, null=True)
    occl_enchashment_status=  models.CharField(max_length=250, blank=True, null=True)
    occl_max_enchashment_leaves=  models.CharField(max_length=250, blank=True, null=True)
    occl_editable=  models.CharField(max_length=250, blank=True, null=True)
    occl_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    occl_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class OrganizationCostCentersYearList(models.Model):
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    occyl_added_by_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    occ_ref=  models.ForeignKey(OrganizationCostCenters, on_delete=models.CASCADE, blank=True, null=True)
    occyl_year_start_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp")
    occyl_year_end_date=  models.DateTimeField(auto_now_add=True,verbose_name="occyl_year_end_date")
    occyl_status=  models.CharField(max_length=250, blank=True, null=True)
    occyl_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    occyl_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class UsersLeaveMaster(models.Model):
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    ulm_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    occ_ref=  models.ForeignKey(OrganizationCostCenters, on_delete=models.CASCADE, blank=True, null=True)
    occl_ref=  models.ForeignKey(OrganizationLeaveType, on_delete=models.CASCADE, blank=True, null=True)
    occyl_ref=  models.ForeignKey(OrganizationCostCentersYearList, on_delete=models.CASCADE, blank=True, null=True)
    #do check this id
    ulm_added_by_ref_id=  models.CharField(max_length=250, blank=True, null=True)
    ulm_allotted_leaves=  models.CharField(max_length=250, blank=True, null=True)
    ulm_leaves_used=  models.CharField(max_length=250, blank=True, null=True)
    ulm_expiry_date=  models.DateTimeField(auto_now_add=True,verbose_name="ulm_expiry_date")
    ulm_status=  models.CharField(max_length=250, blank=True, null=True)
    ulm_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    ulm_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)


class UsersLeaveApplications(models.Model):

    org_ref=  models.ForeignKey(OrganizationLeaveType, on_delete=models.CASCADE, blank=True, null=True)
    ula_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    occl_ref=  models.ForeignKey(OrganizationCostCentersLeaveType, on_delete=models.CASCADE, blank=True, null=True)
    ulm_ref=  models.ForeignKey(UsersLeaveMaster, on_delete=models.CASCADE, blank=True, null=True)
    #do check this  twi fields
    ula_approved_by_ref_u_id=  models.CharField(max_length=250, blank=True, null=True)
    ula_cc_to_ref_u_id=  models.CharField(max_length=250, blank=True, null=True)
    ula_approved_date=  models.DateTimeField(auto_now_add=True,verbose_name="ula_approved_date")
    ula_reason_for_leave=  models.CharField(max_length=250, blank=True, null=True)
    ula_contact_details=  models.CharField(max_length=250, blank=True, null=True)
    ula_file=  models.CharField(max_length=250, blank=True, null=True)
    ula_file_path=  models.CharField(max_length=250, blank=True, null=True)
    ula_file_base_url=  models.CharField(max_length=250, blank=True, null=True)
    ula_cc_mail_sent=  models.CharField(max_length=250, blank=True, null=True)
    ula_from_date=  models.DateTimeField(auto_now_add=True,verbose_name="ula_from_date")
    ula_to_date=  models.DateTimeField(auto_now_add=True,verbose_name="ula_to_date")
    ula_from_session=  models.CharField(max_length=250, blank=True, null=True)
    ula_to_session=  models.CharField(max_length=250, blank=True, null=True)
    ula_no_of_days_leaves=  models.CharField(max_length=250, blank=True, null=True)
    ula_approved_leaves=  models.CharField(max_length=250, blank=True, null=True)
    ula_rejected_leaves=  models.CharField(max_length=250, blank=True, null=True)
    ula_pending_leaves=  models.CharField(max_length=250, blank=True, null=True)
    ula_balanced_leaves=  models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class UserLeaveAllotmentList(models.Model):

    org_ref=  models.ForeignKey(OrganizationLeaveType, on_delete=models.CASCADE, blank=True, null=True)
    occ_ref=  models.ForeignKey(OrganizationCostCenters, on_delete=models.CASCADE, blank=True, null=True)
    occyl_ref=  models.ForeignKey(OrganizationCostCentersYearList, on_delete=models.CASCADE, blank=True, null=True)
    occl_ref=  models.ForeignKey(OrganizationCostCentersLeaveType, on_delete=models.CASCADE, blank=True, null=True)
    ulm_ref=  models.ForeignKey(UsersLeaveMaster, on_delete=models.CASCADE, blank=True, null=True)
    ulal_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    ula_ref=  models.ForeignKey(UsersLeaveApplications, on_delete=models.CASCADE, blank=True, null=True)
    ulal_allotted_leaves=  models.CharField(max_length=250, blank=True, null=True)

    ulal_from_date=  models.DateTimeField(auto_now_add=True,verbose_name="ulal_from_date")
    ulal_to_date=  models.DateTimeField(auto_now_add=True,verbose_name="ulal_to_date")
    ulal_expiry_date=  models.DateTimeField(auto_now_add=True,verbose_name="ulal_expiry_date")
    ulal_status=  models.CharField(max_length=250, blank=True, null=True)
    ulal_type=  models.CharField(max_length=250, blank=True, null=True)
    ulal_type_of_allotment=  models.CharField(max_length=250, blank=True, null=True)
    ulal_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    ulal_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class UserLeaveList(models.Model):
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    ull_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    olt_ref=  models.ForeignKey(OrganizationLeaveType, on_delete=models.CASCADE, blank=True, null=True)
    occ_ref=  models.ForeignKey(OrganizationCostCenters, on_delete=models.CASCADE, blank=True, null=True)
    #do check this id
    ull_added_by_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='ull_added_by_ref_user',blank=True, null=True)
     #do check this id
    ull_ref_ohcy_id=  models.CharField(max_length=250, blank=True, null=True)
    ull_no_of_allotted_leaves=  models.CharField(max_length=250, blank=True, null=True)
    ull_no_of_leaves_used=  models.CharField(max_length=250, blank=True, null=True)
    ull_status=  models.CharField(max_length=250, blank=True, null=True)
    ull_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    ull_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class  ProjectCategoriesChecklist(models.Model):
    org_ref =  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True,related_name='org_ref')
    pcc_added_by_ref_user =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    pc_ref=  models.ForeignKey(ProjectCategories, on_delete=models.CASCADE, blank=True, null=True,related_name='pc_ref')
    pcc_name=  models.CharField(max_length=250, blank=True, null=True)
    pcc_billable=  models.CharField(max_length=250, blank=True, null=True)
    pcc_status=  models.CharField(max_length=250, blank=True, null=True)
    pcc_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    pcc_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)


class TaskProjectCategoriesChecklist(models.Model):
    p_ref=  models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True)
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    tpcc_added_by_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    pc_ref=  models.ForeignKey(ProjectCategories, on_delete=models.CASCADE, blank=True, null=True)
    pcc_ref=  models.ForeignKey(ProjectCategoriesChecklist, on_delete=models.CASCADE, blank=True, null=True)
    opg_ref=  models.ForeignKey(OrgPeopleGroup, on_delete=models.CASCADE, blank=True, null=True)
    
    tpcc_name=  models.CharField(max_length=250, blank=True, null=True)
    tpcc_status=  models.CharField(max_length=250, blank=True, null=True)
    tpcc_billable=  models.CharField(max_length=250, blank=True, null=True)
    #do check this id
    tpcc_assignee_people_ref_u_id=  models.CharField(max_length=250, blank=True, null=True)
    tpcc_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="tpcc_m_date")
    #do check this id
    # tpcc_assignee_people_ref_u_id=  models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)
 


class TimesheetMaster(models.Model):
    tm_timesheet_date=  models.DateTimeField(auto_now_add=True,verbose_name="tm_timesheet_date")
    tm_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='tm_ref_user', blank=True, null=True)
    ula_ref=  models.ForeignKey(UsersLeaveApplications, on_delete=models.CASCADE, blank=True, null=True)
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    tm_approver_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='tm_approver_ref_user',  blank=True, null=True)
    tm_approved_date=  models.DateTimeField(auto_now_add=True,verbose_name="tm_approved_date")
    tm_status=  models.CharField(max_length=250, blank=True, null=True)
    tm_leave_holiday_conflict=  models.CharField(max_length=250, blank=True, null=True)
    tm_auto_approved=  models.CharField(max_length=250, blank=True, null=True)
    tm_deadline_status=  models.CharField(max_length=250, blank=True, null=True)
    tm_deadline_date=  models.DateTimeField(auto_now_add=True,verbose_name="tm_deadline_date")
    tm_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    tm_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)

class TimesheetMasterDetails(models.Model):
    tmd_timesheet_date=  models.DateTimeField(auto_now_add=True,verbose_name="tmd_timesheet_date")
    tmd_ref_tm=  models.ForeignKey(TimesheetMaster, on_delete=models.CASCADE, blank=True, null=True)
    tmd_ref_user=  models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='tmd_ref_user', blank=True, null=True)
    org_ref=  models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True)
    c_ref=  models.ForeignKey(Clients, on_delete=models.CASCADE, blank=True, null=True)
    p_ref=  models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True)
    tpcc_ref=  models.ForeignKey(TaskProjectCategoriesChecklist, on_delete=models.CASCADE, blank=True, null=True)
    ula_ref=  models.ForeignKey(UsersLeaveApplications, on_delete=models.CASCADE, blank=True, null=True)
    tmd_approver_ref_user =  models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='tmd_approver_ref_user', blank=True, null=True)
    tmd_timer_status=  models.CharField(max_length=250, blank=True, null=True)
    tmd_start_time=  models.DateTimeField(auto_now_add=True,verbose_name="tmd_start_time")
    tmd_description=  models.CharField(max_length=250, blank=True, null=True)
    tmd_status=  models.CharField(max_length=250, blank=True, null=True)
    tmd_approved_date=  models.DateTimeField(auto_now_add=True,verbose_name="tmd_approved_date")
    tmd_halfday_status=  models.CharField(max_length=250, blank=True, null=True)
    tmd_leave_holiday_conflict=  models.CharField(max_length=250, blank=True, null=True)
    tmd_auto_approved=  models.CharField(max_length=250, blank=True, null=True)
    tmd_deadline_status=  models.CharField(max_length=250, blank=True, null=True)
    tmd_deadline_date=  models.DateTimeField(auto_now_add=True,verbose_name="tmd_deadline_date")
    tmd_c_date=  models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    tmd_m_date=  models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)


class PrefixSuffix(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    prefix=  models.CharField(max_length=250, blank=True, null=True)
    suffix =  models.CharField(max_length=250, blank=True, null=True)
    prefixsuffix_status =  models.CharField(max_length=250, blank=True, null=True)
    added_date =  models.DateTimeField(auto_now_add=True,verbose_name="added_date")
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)




class People(models.Model):
    user =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    user_reporting_manager_ref   = models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='user_reporting_manager_ref', blank=True, null=True)
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE,related_name='CustomCenter', blank=True, null=True) 
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)

    prefix_suffix  =  models.ForeignKey(PrefixSuffix, on_delete=models.SET_NULL, blank=True, null=True)
    department =  models.ForeignKey(OrganizationDepartment, on_delete=models.CASCADE, blank=True, null=True)
    role  =  models.ForeignKey(OrganizationRoles, on_delete=models.CASCADE, blank=True, null=True)
    cost_center=  models.ForeignKey(OrganizationCostCenters, on_delete=models.CASCADE, blank=True, null=True)
    tags=  models.JSONField(blank=True, null=True)

    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)

    sort =  models.IntegerField( blank=True, null=True)


class Tag(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    tag_name  =  models.CharField(max_length=250, blank=True, null=True)
    added_date =  models.DateTimeField(auto_now_add=True,verbose_name="added_date")
    tage_status   =  models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)


class TimeSheet(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    client =  models.ForeignKey(Clients, on_delete=models.CASCADE, blank=True, null=True)
    project=  models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True)
    task=  models.ForeignKey(TaskProjectCategories, on_delete=models.CASCADE, blank=True, null=True)
    time_spent=  models.CharField(max_length=250, blank=True, null=True)
    description=  models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    timesheet_status=  models.CharField(max_length=250, blank=True, null=True)
    timesheet_date_timestamp=  models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)

class MasterLeaveTypes(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    leave_applicable_for= models.ForeignKey(Center, on_delete=models.CASCADE,related_name='Center', blank=True, null=True)
    accrude_monthly =models.BooleanField(default=False, blank=True, null=True)
    encashment=models.BooleanField(default=False, blank=True, null=True)

    leave_title=models.CharField(max_length=250, blank=True, null=True)
    leave_type= models.CharField(max_length=250, blank=True, null=True)
    no_of_leaves=models.CharField(max_length=250, blank=True, null=True)
    carry_forward_per= models.CharField(max_length=250, blank=True, null=True)
    gracefull_days=models.CharField(max_length=250, blank=True, null=True)
    max_encashments=models.CharField(max_length=250, blank=True, null=True)
    action=  models.CharField(max_length=250, blank=True, null=True)
    description=models.CharField(max_length=250, blank=True, null=True)
    yearly_leaves=models.CharField(max_length=250, blank=True, null=True)
    monthly_leaves=models.CharField(max_length=250, blank=True, null=True)
    
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)


class leaveApplication(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    leave_type  =  models.ForeignKey(MasterLeaveTypes, on_delete=models.CASCADE, blank=True, null=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    reason=  models.CharField(max_length=250, blank=True, null=True)
    contact_details=  models.CharField(max_length=250, blank=True, null=True)
    leave_application_file_path=  models.CharField(max_length=250, blank=True, null=True)
    cc_to =  models.JSONField(blank=True, null=True)
    leaveApplication_from_date=  models.CharField(max_length=250, blank=True, null=True)
    leaveApplication_to_date=  models.CharField(max_length=250, blank=True, null=True)
    days=  models.CharField(max_length=250, blank=True, null=True)
    from_session=  models.CharField(max_length=250, blank=True, null=True)
    to_session=  models.CharField(max_length=250, blank=True, null=True)
    balance=  models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)

    approved_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='approved_by', blank=True, null=True)
    approved_date =  models.CharField(max_length=250, blank=True, null=True)
    approved_state =  models.CharField(max_length=250, blank=True, null=True)
    sort =  models.IntegerField( blank=True, null=True)
    request =  models.CharField(max_length=250, default='LEAVE_REQUEST', blank=True, null=True)

class Profile(models.Model):
    first_name =  models.CharField(max_length=250, blank=True, null=True)
    last_name=  models.CharField(max_length=250, blank=True, null=True)
    designation=  models.CharField(max_length=250, blank=True, null=True)
    email_id=  models.CharField(max_length=250, blank=True, null=True)
    user_address_details=  models.CharField(max_length=250, blank=True, null=True)
    country=  models.CharField(max_length=250, blank=True, null=True)
    state= models.CharField(max_length=250, blank=True, null=True)
    city= models.CharField(max_length=250, blank=True, null=True)
    address=models.CharField(max_length=250, blank=True, null=True)
    phone_number= models.CharField(max_length=250, blank=True, null=True)
    dob= models.CharField(max_length=250, blank=True, null=True)
    tags=models.CharField(max_length=250, blank=True, null=True)
    postal_code=models.CharField(max_length=250, blank=True, null=True)
    base64 = models.TextField(max_length=50000, blank=True, null=True)
    user_profile_photo= models.CharField(max_length=250, blank=True, null=True)
    photo_path= models.CharField(max_length=2000, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

 
class SubscriptionPlan(models.Model):
    plan = models.CharField(max_length=250, blank=True, null=True)
    type= models.CharField(max_length=250, blank=True, null=True)
    no_of_subscribers = models.CharField(max_length=250, blank=True, null=True)
    amt_per_user = models.CharField(max_length=250, blank=True, null =True)
    total_amount = models.IntegerField(blank=True, null=True)
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null =True)
    days_left = models.DateField(blank=True, null =True)
    reg_users = models.CharField(max_length=250, blank=True, null=True)
    c_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    m_timestamp = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)
    sort =  models.IntegerField( blank=True, null=True)

class OfficeWorkingDays(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    updated_by =  models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)

    office_working_days_all =  models.JSONField(blank=True, null=True)
    office_working_days =  models.JSONField(blank=True, null=True)


    created_time = models.DateTimeField(auto_now_add=True,verbose_name="Create_TimeStamp",blank=True,null=True)
    updated_time = models.DateTimeField(auto_now_add=True,verbose_name="Last_Update_TimeStamp",blank=True,null=True)


class NotificationCenter(models.Model):
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,blank=True,null=True)
    # user      = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    project   = models.ForeignKey(Projects, on_delete=models.CASCADE, blank=True, null=True)
    notify    = models.CharField(max_length=250, blank=True, null=True)
    # msg = models.CharField(max_length=250, blank=True, null=True)
    info      = models.JSONField(blank=True, null=True)
    # is_read   = models.BooleanField(default=False)

    create_timestamp= models.DateTimeField(auto_now_add=True,verbose_name="create_timestamp",blank=True,null=True)
    update_timestamp= models.DateTimeField(auto_now=True,verbose_name="last_update_timestamp",blank=True,null=True)