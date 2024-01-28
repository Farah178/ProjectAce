from django.db.models import fields
# from fitbit.views import getactivitylog
from .models import *
from  rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):


    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user

def convert_task_list_string(task_list):
    task_list_string = ''
    for u in task_list:
        if task_list_string == '':
            task_list_string = str(u['task_name'])
        else:
            task_list_string = str(task_list_string) + ',' + str(u['task_name'])
    return task_list_string

class ProjectsSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='c_ref.c_name')
    reporting_manager_first_name = serializers.SerializerMethodField()
    reporting_manager_last_name = serializers.SerializerMethodField()
    reporting_manager_gender = serializers.SerializerMethodField()
    reporting_manager_designation = serializers.SerializerMethodField()
    reporting_manager_email = serializers.SerializerMethodField()
    reporting_manager_phone_no = serializers.SerializerMethodField()

    approver_manager_first_name = serializers.SerializerMethodField()
    approver_manager_last_name = serializers.SerializerMethodField()
    approver_manager_gender = serializers.SerializerMethodField()
    approver_manager_designation = serializers.SerializerMethodField()
    approver_manager_email = serializers.SerializerMethodField()
    approver_manager_phone_no = serializers.SerializerMethodField()

    # Add other fields as needed
    p_status_color = serializers.SerializerMethodField()
    task_list_converted = serializers.SerializerMethodField()

    def get_user_field(self, obj, field_name):
        user_id = getattr(obj, 'approve_manager_ref_id')  # Get the ID from the 'approve_manager_ref_id' field
        approver_data = CustomUser.objects.get(id=user_id) if user_id else None
        return getattr(approver_data, field_name) if approver_data else None

    def get_user_field(self, obj, field_name, ref_id_field):
        user_id = getattr(obj, ref_id_field)
        user_data = CustomUser.objects.get(id=user_id) if user_id else None
        return getattr(user_data, field_name) if user_data else None

    def get_reporting_manager_first_name(self, obj):
        return self.get_user_field(obj, 'u_first_name', 'reporting_manager_ref_id')

    def get_reporting_manager_last_name(self, obj):
        return self.get_user_field(obj, 'u_last_name', 'reporting_manager_ref_id')

    def get_reporting_manager_gender(self, obj):
        return self.get_user_field(obj, 'u_gender', 'reporting_manager_ref_id')

    def get_reporting_manager_designation(self, obj):
        return self.get_user_field(obj, 'u_designation', 'reporting_manager_ref_id')

    def get_reporting_manager_email(self, obj):
        return self.get_user_field(obj, 'u_email', 'reporting_manager_ref_id')

    def get_reporting_manager_phone_no(self, obj):
        return self.get_user_field(obj, 'u_phone_no', 'reporting_manager_ref_id')

    def get_approver_manager_first_name(self, obj):
        return self.get_user_field(obj, 'u_first_name', 'approve_manager_ref_id')

    def get_approver_manager_last_name(self, obj):
        return self.get_user_field(obj, 'u_last_name', 'approve_manager_ref_id')

    def get_approver_manager_gender(self, obj):
        return self.get_user_field(obj, 'u_gender', 'approve_manager_ref_id')

    def get_approver_manager_designation(self, obj):
        return self.get_user_field(obj, 'u_designation', 'approve_manager_ref_id')

    def get_approver_manager_email(self, obj):
        return self.get_user_field(obj, 'u_email', 'approve_manager_ref_id')

    def get_approver_manager_phone_no(self, obj):
        return self.get_user_field(obj, 'u_phone_no', 'approve_manager_ref_id')

    def get_p_status_color(self, obj):
        p_status = obj.p_status
        if p_status == "Open":
            return 'orange'
        elif p_status == "Pending":
            return 'red'
        elif p_status == "Completed":
            return 'green'
        else:
            return None  # If no condition matches, return None or any default value you prefer

    def get_task_list_converted(self, obj):
        return convert_task_list_string(obj.project_related_task_list)

    class Meta:
        model = Projects
        fields = '__all__'






class CustomUserTableSerializers(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'

class ClientsDmsSerializers(serializers.ModelSerializer):
    class Meta:
        model = ClientsDms
        fields = '__all__'

class OrganizationCostCentersSerializers(serializers.ModelSerializer):
    class Meta:
        model =  OrganizationCostCenters
        fields = '__all__'

class ClientsOtherContactDetailsSerializers(serializers.ModelSerializer):
    class Meta:
        model =  ClientsOtherContactDetails
        fields = '__all__'

class OrganizationRolesSerializers(serializers.ModelSerializer):
    class Meta:
        model =  OrganizationRoles
        fields = '__all__'


class OrganizationTableSerializers(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'

class OrganizationDepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrganizationDepartment
        fields = '__all__'

class ClientsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Clients
        fields = '__all__'

class TaskProjectCategoriesSerializers(serializers.ModelSerializer):
    class Meta:
        model = TaskProjectCategories
        fields = '__all__'

class ProjectsSerializers(serializers.ModelSerializer):
    class Meta:
        model = Projects
        fields = '__all__'


class ProjectCategoriesFilesTemplatesSerializers(serializers.ModelSerializer):
    class Meta:
        model = ProjectCategoriesFilesTemplates
        fields = '__all__'

class TypeOfIndustriesSerializers(serializers.ModelSerializer):
    class Meta:
        model =TypeOfIndustries
        fields = '__all__'

class ProjectCategoriesSerializers(serializers.ModelSerializer):
    class Meta:
        model = ProjectCategories
        fields = '__all__'

class ProjectStatusMainCategorySerializers(serializers.ModelSerializer):
    class Meta:
        model = ProjectStatusMainCategory
        fields = '__all__'


class OrgPeopleGroupsSerializers(serializers.ModelSerializer):
    class Meta:
        model = OrgPeopleGroup
        fields = '__all__'


class ProjectHistorySerializers(serializers.ModelSerializer):
    class Meta:
        model = ProjectHistory
        fields = '__all__'


class TaskProjectCategoriesSerializers(serializers.ModelSerializer):
    class Meta:
        model : TaskProjectCategories
        fields = '__all__'


class ProjectStatusSubCategorySerializers(serializers.ModelSerializer):
    class Meta:
        model = ProjectStatusSubCategory
        fields = '__all__'


class ProjectFilesCategorySerializers(serializers.ModelSerializer):
    class Meta:
        model = ProjectFiles
        fields = '__all__'

class GeoZonesCategorySerializers(serializers.ModelSerializer):
    class Meta:
        model : GeoZones
        fields = '__all__'
        

class GeoTimezonesSerializers(serializers.ModelSerializer):
    class Meta:
        model = GeoTimezones
        fields = '__all__'

class GeoCurrenciesSerializers(serializers.ModelSerializer):
    class Meta:
        model = GeoCurrencies
        fields = '__all__'


class GeoCountriesCurrenciesSerializers(serializers.ModelSerializer):
    class Meta:
        model = GeoCountriesCurrencies
        fields = '__all__'

class GeoStatesSerializers(serializers.ModelSerializer):
    class Meta:
        model = GeoStates
        fields = '__all__'

class GeoCitiesSerializers(serializers.ModelSerializer):
    class Meta:
        model = GeoCities
        fields = '__all__'

class GeoContinentsSerializers(serializers.ModelSerializer):
    class Meta:
        model = GeoContinents
        fields = '__all__'

class GeoSubContinentsSerializers(serializers.ModelSerializer):
    class Meta:
        model = GeoSubContinents
        fields = '__all__'



class ProductDetailsSerializers(serializers.ModelSerializer):
    class Meta:
        model = ProductDetails
        fields = '__all__'







