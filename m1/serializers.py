from django.db.models import fields
from .models import *
from  rest_framework import serializers

class TimespentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timespent
        fields = '__all__'


class TimeSheetSerilizer(serializers.ModelSerializer):
    # client = serializers.StringRelatedField()
    class Meta:
        model = TimeSheets
        fields = '__all__'
        

class TimeSheetdetailSerilizer(serializers.ModelSerializer):
    time_spent =serializers.CharField(source ='time_spent.name')
    class Meta:
        model = TimeSheets
        fields = (
            "id"
            "client_id",
            "project_id",
            "task_id",
            "description",
            "time_spent"
        )

class TimesheetsApprovalConfigSerilizer(serializers.ModelSerializer):
    
    class Meta:
        model = TimesheetsApprovalConfig
        fields = '__all__'


class TodaysApprovalSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = TodaysApproval
        fields = '__all__'