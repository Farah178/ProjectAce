from django.shortcuts import render
from rest_framework.response import Response
from requests.api import request
from .serializers import *
from rest_framework.views import APIView 
from rest_framework.generics import GenericAPIView
from .models import *
from rest_framework import status
import base64
from rest_framework.pagination import PageNumberPagination
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from .pagination import *
from rest_framework.generics import ListAPIView
from django.db.utils import IntegrityError
from rest_framework import pagination
from rest_framework.pagination import PageNumberPagination
from .pagination import * 
import random
from .models import *
import time
import datetime
from rest_framework import viewsets
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from django.core.paginator import Paginator
from eztimeapp.backends import *
from django.db.models.functions import ExtractMonth, ExtractYear
from django.utils.timezone import datetime
from datetime import timedelta
from django.utils import timezone
# from m1.tasks import auto_approve_timesheet
from eztimeapp.models import *
# Create your views here.

# class TimeSheetApiViewAll(ListAPIView):
#     pagination_class = EztimeAppPagination
#     queryset = TimeSheets.objects.all()
#     serializer_class = TimeSheetSerilizer
#     

from django.db.models import Q
import datetime

class TimespentAPIView(APIView):
    def post(self,request):
        data = request.data
        name = data.get('name')
        created_datetime =data.get('created_datetime')
        updated_datetime= data.get('updated_datetime')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            if data:
                Timespent.objects.create(name=name
                                        )
                project = Timespent.objects.all().values()
                paginator = Paginator(project,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Data created sucdessfully','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def get(self,request):
        id = request.query_params.get('id')
        if id:
            try:
                all_data = Timespent.objects.filter(id=id).values().order_by('-created_date_time')
                return Response({'result':{'status':'GET by id','data':all_data}})
            except Timespent.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = Timespent.objects.all().values().order_by('-created_date_time')
            return Response({'result':{'status':'All data','data':all_data}})
        

    def put(self, request):
        data = request.data
        id = data.get('id')
        if id:
            data = Timespent.objects.filter(id=id).update(name  = data.get('name')
                    )
            if data:
                    return Response({'message': 'Data Updated Sucessfully.'})
            else:
                response={'message':"Invalid id"}
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': 'Id Required.'})



    def delete(self, request):
        id =self.request.query_params.get('id')
        item = Timespent.objects.filter(id= id)
        if len(item) > 0:
            item.delete()
            return Response({'result':{'Status':'Data Deleted Sucessfully'}})
        else:
            return Response({'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        




class UpdateTimesheetStatus(APIView):
    def get(self, request):
            try:
                reporting_manager_ref_id = self.request.query_params.get('reporting_manager_ref')
                if reporting_manager_ref_id:
                    data = TimeSheets.objects.filter(reporting_manager_ref_id=reporting_manager_ref_id).values('reporting_manager_ref__id')
                    serializer=TimeSheetSerilizer(data, many=True)
                    return Response({'result':{'status':'Filter by user_Id','data':serializer.data}})
                else:
                    return Response({"message": 'time sheet id not found'}, serializer.errors, status=status.HTTP_404_NOT_FOUND)
                
            except TimeSheet.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)  

        # return Response(request.query_params['user_id'])


    def post(self,request):
        res = CheckPermission(request)
        if res[0] == 2:
            return res[1]

        data = request.data 
        time_sheet_id_list = data['time_sheet_id_list']
        approved_state = data['approved_state']
        time_sheet_id = data['time_sheet_id']
        user_id = data['user_id']
        approved_by_manager_id = data['approved_by_manager_id']
        now = datetime.datetime.now()
        date_object = datetime.datetime.now().strftime("%d/%m/%Y")
        print(date_object,'date_object====>')
        # date_object = datetime.datetime.strptime(now_date, "%d/%m/%Y")

        updated_date_time_stamp = time.mktime(datetime.datetime.strptime(date_object, "%d/%m/%Y").timetuple())
                     
        if len(time_sheet_id_list) != 0:
            for i in time_sheet_id_list:
                TimeSheets.objects.filter(id=i).update(
                    approved_state =  approved_state,
                    approved_date_timestamp = updated_date_time_stamp,
                    approved_date=date_object,
                    approved_date_time = now,
                    approved_by_id=approved_by_manager_id
                )

            return Response({'message': 'List of Timesheet status Updated Successfully!'})
        else:
            TimeSheets.objects.filter(id=time_sheet_id).update(
                    approved_state =  approved_state,
                    approved_date_timestamp = updated_date_time_stamp,
                    approved_date_time = now,
                    approved_date=date_object,
                    approved_by_id=approved_by_manager_id
            )
            return Response({'message': 'Timesheet status Updated Successfully!'})
        
from django.db.models.functions import TruncMonth
class TimesheetcalenderAPIView(APIView):
    def get(self, request):
        user_id = request.query_params.get('user_id')
        if user_id:
            timesheet = TimeSheets.objects.filter(Q(created_by=user_id)).values()
            # for j in timesheet:
            #     print(j.applied_date)


            return Response({'result':{'message': 'Get Calender Time Sheet BY USER ID',
            'data':timesheet}})
        else:
            timesheet = TimeSheets.objects.all().values()
            return Response({'result':{'message': 'Get Calender Time Sheet BY ALL',
            'data':timesheet}})


class TimeSheetApiViewAll(APIView):
    def get(self,request):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
            
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        approved_state = request.query_params.get('approved_state')
        user_id= request.query_params.get('user_id')
        project_id= request.query_params.get('project_id')
        timesheet_from_date= request.query_params.get('timesheets_from_date')
        timesheet_to_date= request.query_params.get('timesheets_to_date')
        
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')


        if pagination == 'FALSE':
            all_data = TimeSheets.objects.all().values()
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if user_id:    
            if timesheet_from_date and timesheet_to_date:
                if approved_state:
                    fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())
                    print(fd,'from_Dateee======')
                    print(td,'To_Dateee======')
                    queryset1 = TimeSheets.objects.filter(Q(approved_state=approved_state) & Q(created_by_id=user_id) & Q(applied_date_timestamp__gte=fd)).values().order_by('-created_date_time')


                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(approved_state='APPROVED')& Q(created_by_id=user_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(approved_state='DECLINED')& Q(created_by_id=user_id)).count()

                    yet_to_be_approved_queryset = TimeSheets.objects.filter(Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id))
                    approved_queryset = TimeSheets.objects.filter(Q(approved_state='APPROVED')& Q(created_by_id=user_id))
                    declined_queryset = TimeSheets.objects.filter(Q(approved_state='DECLINED')& Q(created_by_id=user_id))
                    
                    yet_to_be_approved_hours = 0
                    approved_hours = 0
                    declined_hours = 0

                    for i in yet_to_be_approved_queryset:
                        ytb_timespent = i.time_spent
                        yet_to_be_approved_hours = yet_to_be_approved_hours + int(ytb_timespent.split('hr')[0])
                        
                    for j in approved_queryset:
                        a_timespent = j.time_spent
                        approved_hours = approved_hours + int(a_timespent.split('hr')[0])

                    for k in declined_queryset:
                        a_timespent = k.time_spent
                        declined_hours = declined_hours + int(a_timespent.split('hr')[0])



                    
                    total = (yet_to_be_approved_hours+approved_hours+declined_hours)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'request_hours':yet_to_be_approved_hours,
                            'approved_hours':approved_hours,
                            'declined_hours':declined_hours,
                            'total_hours':total,
                            'from_date':timesheet_from_date,
                            'to_date':timesheet_to_date,
                            'from_date_timestamp':fd,
                            'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(queryset1,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY USER ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
        
        if project_id:
            if approved_state:
                    fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())
                    print(fd,'from_Dateee======')
                    print(td,'To_Dateee======')
                    queryset1 = TimeSheets.objects.filter(Q(approved_state=approved_state) & Q(created_by_id=user_id) & Q(applied_date_timestamp__gte=fd) & Q(project_id=project_id)).values().order_by('-created_date_time')


                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(approved_state='YET_TO_APPROVED') & Q(project_id=project_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(approved_state='APPROVED')& Q(project_id=project_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(approved_state='DECLINED')& Q(project_id=project_id)).count()
                    total = (yet_to_be_approved_count+approved_count+declined_count)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'total_hours':total,
                            'from_date':timesheet_from_date,
                            'to_date':timesheet_to_date,
                            'from_date_timestamp':fd,
                            'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(queryset1,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY PROJECT ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
        




        all_data = TimeSheets.objects.all().values().order_by('-created_date_time')
        
        data_pagination = EztimeAppPagination(all_data,page_number,data_per_page,request)

        return Response({'result':{'status':'GET ALL',
            'pagination':{
                'current_page':data_pagination[1]['current_page'],
                'number_of_pages':data_pagination[1]['number_of_pages'],
                'next_url':data_pagination[1]['next_url'],
                'previous_url':data_pagination[1]['previous_url'],
                'has_next':data_pagination[1]['has_next'],
                'has_previous':data_pagination[1]['has_previous'],
                'has_other_pages':data_pagination[1]['has_other_pages'],
            },
            'data':data_pagination[0]
            }})
    

class TimesheetApiViews(APIView):
    def get(self,request):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
        
        key = {'organization_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = request.query_params.get('organization_id')
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')


        if pagination == 'FALSE':
            all_data = TimeSheets.objects.filter(organization_id=organization_id).values().order_by('-created_date_time')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

    
        approved_state = request.query_params.get('approved_state')
        user_id= request.query_params.get('user_id')
        project_id= request.query_params.get('project_id')
        timesheet_from_date= request.query_params.get('timesheets_from_date')
        timesheet_to_date= request.query_params.get('timesheets_to_date')
        

        if user_id:    

            if timesheet_from_date and timesheet_to_date:
                if approved_state:
                    fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())
                    print(fd,'from_Dateee======')
                    print(td,'To_Dateee======')
                    if 'search_key' in request.query_params:
                        search_key = request.query_params.get('search_key')

                        r_cuser = CustomUser.objects.filter(Q(id=user_id) & Q(u_first_name__icontains  = search_key))
                        r_query = Q()
                        for r_entry in r_cuser:
                            r_query = r_query | Q(created_by_id=r_entry.id)
                        print(r_query,'r_query=======1223')
                        if r_query:
                            queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & r_query & Q(approved_state=approved_state) & Q(created_by_id=user_id) & Q(applied_date_timestamp__gte=fd) & Q(applied_date_timestamp__lte=td)).values().order_by('-created_date_time')
                        else:
                            queryset1 =[]
                    else:
                        queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(created_by_id=user_id) & Q(applied_date_timestamp__gte=fd) & Q(applied_date_timestamp__lte=td)).values().order_by('-created_date_time')

                    if approved_state != "YET_TO_APPROVED":
                        for i in queryset1:
                            cuser = CustomUser.objects.get(id = i['approved_by_id'])
                            i['approved_by_first_name'] = cuser.u_first_name
                            i['approved_by_last_name'] = cuser.u_last_name
                            i['approved_by_profile_photo'] = cuser.u_profile_photo
                            i['approved_by_email'] = cuser.u_email
                            i['approved_by_phone_no'] = cuser.u_phone_no

                    for y in queryset1:
                        cuser = CustomUser.objects.get(id = y['created_by_id'])
                        y['created_by_first_name'] = cuser.u_first_name
                        y['created_by_last_name'] = cuser.u_last_name
                        y['created_by_profile_photo'] = cuser.u_profile_photo
                        y['created_by_email'] = cuser.u_email
                        y['created_by_phone_no'] = cuser.u_phone_no


                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id)).count()

                    yet_to_be_approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id))
                    approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id))
                    declined_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id))
                    
                    yet_to_be_approved_hours = 0
                    approved_hours = 0
                    declined_hours = 0

                    for i in yet_to_be_approved_queryset:
                        ytb_timespent = i.time_spent
                        yet_to_be_approved_hours = yet_to_be_approved_hours + int(ytb_timespent.split('hr')[0])
                        
                    for j in approved_queryset:
                        a_timespent = j.time_spent
                        approved_hours = approved_hours + int(a_timespent.split('hr')[0])

                    for k in declined_queryset:
                        a_timespent = k.time_spent
                        declined_hours = declined_hours + int(a_timespent.split('hr')[0])



                    
                    total = (yet_to_be_approved_hours+approved_hours+declined_hours)
                    total_count = (yet_to_be_approved_count+approved_count+declined_count)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'request_hours':yet_to_be_approved_hours,
                            'approved_hours':approved_hours,
                            'declined_hours':declined_hours,
                            'total_hours':total,
                            'total_count':total_count,
                            'from_date':timesheet_from_date,
                            'to_date':timesheet_to_date,
                            'from_date_timestamp':fd,
                            'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(queryset1,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY USER ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})

            else:
                if approved_state:
                    if 'search_key' in request.query_params:
                        search_key = request.query_params.get('search_key')

                        r_cuser = CustomUser.objects.filter(Q(id=user_id) & Q(u_first_name__icontains  = search_key))
                        r_query = Q()
                        for r_entry in r_cuser:
                            r_query = r_query | Q(created_by_id=r_entry.id)
                        print(r_query,'r_query=======1223')
                        if r_query:
                            queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & r_query & Q(approved_state=approved_state)).values().order_by('-created_date_time')
                        else:
                            queryset1 =[]
                    else:        
                        queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(created_by_id=user_id)).values().order_by('-created_date_time')

                    if approved_state != "YET_TO_APPROVED":
                        for i in queryset1:
                            cuser = CustomUser.objects.get(id = i['approved_by_id'])
                            i['approved_by_first_name'] = cuser.u_first_name
                            i['approved_by_last_name'] = cuser.u_last_name
                            i['approved_by_profile_photo'] = cuser.u_profile_photo
                            i['approved_by_email'] = cuser.u_email
                            i['approved_by_phone_no'] = cuser.u_phone_no

                    for y in queryset1:
                        cuser = CustomUser.objects.get(id = y['created_by_id'])
                        y['created_by_first_name'] = cuser.u_first_name
                        y['created_by_last_name'] = cuser.u_last_name
                        y['created_by_profile_photo'] = cuser.u_profile_photo
                        y['created_by_email'] = cuser.u_email
                        y['created_by_phone_no'] = cuser.u_phone_no

                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id)).count()

                    yet_to_be_approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id))
                    approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id))
                    declined_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id))
                    
                    yet_to_be_approved_hours = 0
                    approved_hours = 0
                    declined_hours = 0

                    for i in yet_to_be_approved_queryset:
                        ytb_timespent = i.time_spent
                        yet_to_be_approved_hours = yet_to_be_approved_hours + int(ytb_timespent.split('hr')[0])
                        
                    for j in approved_queryset:
                        a_timespent = j.time_spent
                        approved_hours = approved_hours + int(a_timespent.split('hr')[0])

                    for k in declined_queryset:
                        a_timespent = k.time_spent
                        declined_hours = declined_hours + int(a_timespent.split('hr')[0])



                    
                    total = (yet_to_be_approved_hours+approved_hours+declined_hours)
                    total_count = (yet_to_be_approved_count+approved_count+declined_count)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'request_hours':yet_to_be_approved_hours,
                            'approved_hours':approved_hours,
                            'declined_hours':declined_hours,
                            'total_hours':total,
                            'total_count':total_count,
                            'from_date':timesheet_from_date,
                            'to_date':timesheet_to_date,
                            # 'from_date_timestamp':fd,
                            # 'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(queryset1,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY USER ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})


        if project_id:
            if approved_state:
                    fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())
                    print(fd,'from_Dateee======')
                    print(td,'To_Dateee======')
                    queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(created_by_id=user_id) & Q(applied_date_timestamp__gte=fd) & Q(project_id=project_id)).values().order_by('-created_date_time')

                    if approved_state != "YET_TO_APPROVED":
                        for i in queryset1:
                            cuser = CustomUser.objects.get(id = i['approved_by_id'])
                            i['approved_by_first_name'] = cuser.u_first_name
                            i['approved_by_last_name'] = cuser.u_last_name
                            i['approved_by_profile_photo'] = cuser.u_profile_photo
                            i['approved_by_email'] = cuser.u_email
                            i['approved_by_phone_no'] = cuser.u_phone_no

                    for y in queryset1:
                        cuser = CustomUser.objects.get(id = y['created_by_id'])
                        y['created_by_first_name'] = cuser.u_first_name
                        y['created_by_last_name'] = cuser.u_last_name
                        y['created_by_profile_photo'] = cuser.u_profile_photo
                        y['created_by_email'] = cuser.u_email
                        y['created_by_phone_no'] = cuser.u_phone_no

                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED') & Q(project_id=project_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(project_id=project_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(project_id=project_id)).count()
                    total = (yet_to_be_approved_count+approved_count+declined_count)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'total_hours':total,
                            'from_date':timesheet_from_date,
                            'to_date':timesheet_to_date,
                            'from_date_timestamp':fd,
                            'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(queryset1,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY PROJECT ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
        




        all_data = TimeSheets.objects.filter(Q(organization_id=organization_id)).values().order_by('-created_date_time')
        
        data_pagination = EztimeAppPagination(all_data,page_number,data_per_page,request)

        return Response({'result':{'status':'GET ALL',
            'pagination':{
                'current_page':data_pagination[1]['current_page'],
                'number_of_pages':data_pagination[1]['number_of_pages'],
                'next_url':data_pagination[1]['next_url'],
                'previous_url':data_pagination[1]['previous_url'],
                'has_next':data_pagination[1]['has_next'],
                'has_previous':data_pagination[1]['has_previous'],
                'has_other_pages':data_pagination[1]['has_other_pages'],
            },
            'data':data_pagination[0]
            }})
    
    def post(self, request):
        res = CheckPermission(request)
        if res[0] == 2:
            return res[1]

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        data = request.data
        organization_id = data.get('organization_id')
        created_by = data.get('created_by')
        reporting_manager_ref_id = data.get('reporting_manager_ref')
        approved_date_time = data.get('approved_date_time')
        timesheet_status = data.get('timesheet_status')
        time_spent = data.get('time_spent')
        date = data.get('date')
        response = data.get("response")
        
        if reporting_manager_ref_id is None or int(reporting_manager_ref_id) == 0:
            
            return Response({
                    'error':{'message':'Contact admin to add reporting manager',
                    'detail':"Reporting manager cannot be null or 0",
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
            return Response({
                    'error':{'message':'You organization do not have Timesheets Approval Config.',
                    'description':"Timesheets Approval Config",
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND) 

        if date == None: 
            return Response({
                    'error':{'message':'date is mandatory',
                    'detail':"Check the structure your passing DD/MM/YYYY",
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
        try:
            applied_date = time.mktime(datetime.datetime.strptime(date, "%d/%m/%Y").timetuple())
        except ValueError:
            return Response({
                'error':{'message':'Incorrect data format',
                'detail':"Data format, should be DD/MM/YYYY",
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        try:
            user_id = CustomUser.objects.get(id=created_by)
        except CustomUser.DoesNotExist:
            return Response({
                'error':{'message':'User with '+ str(created_by) + ' id does not exist',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)


        timesheets = []
        flag = 0
        for item in response:
            task_id = item.get('task_id')
            time_spent = item.get('time_spent')
            project_id = item.get('project_id')
            client_id = item.get('client_id')        
            description = item.get("description")




            if not task_id:
                return Response({'result': {'status': 'Error', 'message': 'task_id is missing or invalid.'}})
            print(project_id,'project_id==========>')
            # name = Timespent.objects.create(name=time_spent)
            try:
                project_object = Projects.objects.get(id = project_id)
            except Projects.DoesNotExist:
                return Response({
                'error':{'message':'Project with '+ str(project_id) + ' id does not exist',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
                
            
            for i in project_object.project_related_task_list:
                if 'id' in i :
                    print(i['id'],'i=====>',task_id,"task_id=>")
                    if int(i['id']) == int(task_id):
                        print('if=====>',i,'i=====>',task_id,"task_id=>")

                        flag = 1
                        dic ={
                            "id": i['id'], 
                            "task_name": i['task_name'], 
                            "billable_type": i['billable_type']
                        }
                    else:
                        print('else=====>')
            if flag == 0:
                return Response({
                    'error':{'message':'tast id '+str(task_id) + ' does not realted to '+ str(project_object.p_name)+  ' Project',
                    'detail':'project_id '+str(project_object.id) + ' tast_id '+str(task_id) ,
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
               
            

            dic_create = {
                "organization_id":organization_id,
                "created_date_time":date,
                "created_by_id":created_by,
                "reporting_manager_ref_id":reporting_manager_ref_id,
                "approved_date_time":approved_date_time,
                "approved_state":'YET_TO_APPROVED',
                "time_spent":time_spent,
                "description":description,
                "client_id":client_id,
                "project_id":project_id,
                "project_category":project_object.task_project_category_list,
                "task_worked_list":dic,
                "applied_date_timestamp":applied_date,
                "applied_date":date
            }
            print(dic_create,'dic_create====>')
            all_data = TimeSheets.objects.create(**dic_create)

            timesheets.append(dic_create)


        if timesheets:
            return Response({'result':{'message': 'TimeSheet created successfully','data':timesheets}})
        else:
            return Response({
            'error':{'message':'Issue with data!',
            'detail':'contact backend developer',
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = TimeSheets.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'message': 'Timesheet Deleted'}})


class ProjectbyClient(APIView):
    def get(self,request):
        project_id = request.query_params.get('project_id')
        client_id = request.query_params.get('client_id')
        if client_id:
            appdata = Projects.objects.filter(c_ref_id=client_id).values().order_by('-p_m_date')
            return Response({'result':{'message': 'Project by client','data':appdata}})        
        elif project_id:
            appdata = Projects.objects.filter(id=project_id).values().order_by('-p_m_date')
            return Response({'result':{'message': 'Project by project_id','data':appdata}})    
        else:
            return Response({
                    'error':{'message':'parameter missing !',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
                       
class TaskbyProjects(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        project_id= request.query_params.get('project_id')
        if project_id:
            appdata = Projects.objects.filter(id=project_id).values().order_by('-p_m_date')
            return Response({'result':{'status':'GET Task by project_id','data':appdata}})
        else:
            return Response({'result':{'status':'project_id does not exist'}})





        
    def delete(self, request,time_id):
        item = TimeSheets.objects.get(id=time_id)
        if item:
            item.delete()
            return Response({"message":"data Deleted Sucessfully"})
        else:
            return Response({"error":"Id Required."},status=status.HTTP_404_NOT_FOUND)



class TimesheetApprovalConfigAPIView(APIView):
    def post(self,request):
        data = request.data
        module = data.get('module')
        user_id = data.get('user_id')
        menu = data.get('menu')
        approval_period = data.get("approval_period")
        days_to_approve = data.get("days_to_approve")
        auto_approve = data.get("auto_approve")
        active_status = data.get("active_status")
        approved_by_user_id= data.get("approved_by_user")
        if data:
            all_data = TimesheetsApprovalConfig.objects.create(
                approval_period=approval_period,
                days_to_approve=days_to_approve,
                auto_approve=auto_approve,
                active_status=active_status,
                approved_by_user_id=approved_by_user_id
            )        
            return Response({'message': {'TimesheetApprovedConfiguration Created Successfully'}})
        else:
            return Response({'message':'Data Required'},status=status.HTTP_400_BAD_REQUEST)

    def get(self,request):
        if request:
            data = TimesheetsApprovalConfig.objects.all().values().order_by('-created_date_time')
            return Response({'message':data})
        else:
            return Response('Timesheet get auto approved if deadline date is crossed')
    


class TodayapprovalTimesheetAPIView(APIView):
    def post(self,request):
        data = request.data
        s_no = data.get("s_no")
        people_id = data.get("people")
        timesheets_id = data.get("active_status")
        saved_on = data.get('saved_on')
        created_date_time= data.get("created_date_time")
        approved_status = data.get('approved_status')
        action = data.get('action')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)  
        try:

            TodaysApproval.objects.create(s_no= s_no, 
                                        people_id=people_id,
                                        timesheets_id=timesheets_id,
                                        saved_on=saved_on,
                                        created_date_time = created_date_time,
                                        approved_status = approved_status,
                                        action = action
                            )
            approved_data = TodaysApproval.objects.all().values()
            paginator = Paginator(approved_data,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Data successfully created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)



    def get(self,request):
        
        key = {'organization_id','page_number','data_per_page'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = request.query_params.get('organization_id')
        date = request.query_params.get('date')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')

        user_id = request.query_params.get('user_id')
        approved_state = request.query_params.get('approved_state')

        created_date_time = datetime.datetime.now()
        
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            all_data = TimeSheets.objects.filter(organization_id=organization_id).values().order_by('-created_date_time')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})


        if approved_state:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')

                r_cuser = CustomUser.objects.filter(Q(u_first_name__icontains  = search_key))
                r_query = Q()
                for r_entry in r_cuser:
                    r_query = r_query | Q(created_by_id=r_entry.id)

                print(r_query,'r_query====>')
                if r_query:
                    queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & r_query & Q(approved_state=approved_state)& Q(created_date_time__date=created_date_time) ).values().order_by('-created_date_time')
                else:
                    queryset = []
            else:    
                queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(created_date_time__date=created_date_time)).values().order_by('-created_date_time')

            if approved_state != "YET_TO_APPROVED":
                for i in queryset:
                    cuser = CustomUser.objects.get(id = i['approved_by_id'])
                    i['approved_by_first_name'] = cuser.u_first_name
                    i['approved_by_last_name'] = cuser.u_last_name
                    i['approved_by_profile_photo'] = cuser.u_profile_photo
                    i['approved_by_email'] = cuser.u_email
                    i['approved_by_phone_no'] = cuser.u_phone_no

            for y in queryset:
                cuser = CustomUser.objects.get(id = y['created_by_id'])
                y['created_by_first_name'] = cuser.u_first_name
                y['created_by_last_name'] = cuser.u_last_name
                y['created_by_profile_photo'] = cuser.u_profile_photo
                y['created_by_email'] = cuser.u_email
                y['created_by_phone_no'] = cuser.u_phone_no

            data_pagination = EztimeAppPagination(queryset,page_number,data_per_page,request)
            return Response({'result':{'status':'GET Timesheet with user_id',
                    'pagination':{
                        'current_page':data_pagination[1]['current_page'],
                        'number_of_pages':data_pagination[1]['number_of_pages'],
                        'next_url':data_pagination[1]['next_url'],
                        'previous_url':data_pagination[1]['previous_url'],
                        'has_next':data_pagination[1]['has_next'],
                        'has_previous':data_pagination[1]['has_previous'],
                        'has_other_pages':data_pagination[1]['has_other_pages'],
                    },
                    'data':data_pagination[0]
                    }})
        
        else:
            all_data = TimeSheets.objects.filter(Q(organization_id=organization_id)).values().order_by('-created_date_time')
            
            data_pagination = EztimeAppPagination(all_data,page_number,data_per_page,request)

            return Response({'result':{'status':'GET ALL',
                'pagination':{
                    'current_page':data_pagination[1]['current_page'],
                    'number_of_pages':data_pagination[1]['number_of_pages'],
                    'next_url':data_pagination[1]['next_url'],
                    'previous_url':data_pagination[1]['previous_url'],
                    'has_next':data_pagination[1]['has_next'],
                    'has_previous':data_pagination[1]['has_previous'],
                    'has_other_pages':data_pagination[1]['has_other_pages'],
                },
                'data':data_pagination[0]
                }})
        
        
    def delete(self,request,pk):
        test = (0,{})
        all_values = TodaysApproval.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
            'error':{'message':'Record not found!',
            'status_code':status.HTTP_404_NOT_FOUND,
            }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})
            

class GetValuesForAddTimeStamp(APIView):
    def get(self, request):
        if request.GET.get('client_id') and not request.GET.get('project_id') and not request.GET.get('task_name') :
            project_obj = Projects.objects.filter(c_ref_id=request.GET.get('client_id')).values('id', 'p_name')
            return Response({'data': project_obj})
        if request.GET.get('client_id') and request.GET.get('project_id') and not request.GET.get('task_name'):
            project_obj = Projects.objects.filter(id=request.GET.get('project_id'), c_ref_id=request.GET.get('client_id')).values('id', 'p_name', 'project_related_task_list')
            return Response({'data': project_obj})
        if request.GET.get('client_id') and request.GET.get('project_id') and request.GET.get('task_name'):
            time_data = []
            timeDict = {}
            for i in range(1, 9):
                timeDict['time'] = str(i)+" hr"
                time_data.append(timeDict)
                timeDict = {}

            return Response(time_data)
 
        return Response("hello")


class ManageremployeelistTimesheetAPIView(APIView):
    def get(self, request):
        if request.query_params:
            reporting_manager_ref_id = request.query_params.get('reporting_manager_ref_id')
            user_role_id = request.query_params.get('user_role_id') 

            manager_obj = TimeSheets.objects.filter(reporting_manager_ref_id=reporting_manager_ref_id).values('description', 'client_id', 'status', 'project', 'task', 'time_spent', 'project__p_name', 'task__task_name', 'reporting_manager_ref__u_first_name')
            print('manager_obj====>>>>>>>>', manager_obj)

            return Response({'manager': manager_obj})
        return Response([])


class MonthlyTimeSheetAPIView(APIView):
    def get(self,request):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
        key = {'organization_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = request.query_params.get('organization_id')

        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        approved_state = request.query_params.get('approved_state')
        user_id= request.query_params.get('user_id')
        project_id= request.query_params.get('project_id')
        timesheet_from_date= request.query_params.get('timesheets_from_date')
        pagination = request.query_params.get('pagination')

        if pagination == 'FALSE':
            all_data = TimeSheets.objects.filter(organization_id=organization_id).values().order_by('-created_date_time')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})
        
        timesheet_list = []
        
        if user_id:    
            if timesheet_from_date:
                x = timesheet_from_date.split('/')
                if int(x[1]) == 12:
                    add = int(x[2])+1
                    timesheet_to_date = x[0]+'/01/'+str(add)
                else:
                    add = int(x[1])+1
                    if int(add) >= 10:
                        timesheet_to_date = x[0]+'/'+str(add)+'/'+x[2]
                    else:
                        timesheet_to_date = x[0]+'/0'+str(add)+'/'+x[2]

                if approved_state:
                    fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())
                    print(fd,'from_Dateee======')
                    print(td,'To_Dateee======')
                    
                    if 'search_key' in request.query_params:
                        search_key = request.query_params.get('search_key')

                        r_cuser = CustomUser.objects.filter(Q(u_first_name__icontains  = search_key))
                        r_query = Q()
                        for r_entry in r_cuser:
                            r_query = r_query | Q(created_by_id=r_entry.id)

                        print(r_query,'r_query====>')
                        if r_query:
                            queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & r_query & Q(approved_state=approved_state) & Q(applied_date_timestamp__gte=fd)& Q(applied_date_timestamp__lt=td)).values().order_by('-created_date_time')
                        else:
                            queryset1 = []
                    else:      
                        queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(applied_date_timestamp__gte=fd)& Q(applied_date_timestamp__lt=td)).values().order_by('-created_date_time')
                    
                    for i in queryset1:
                        created_by_cuser = CustomUser.objects.get(id=i['created_by_id'])
                        
                        dic = {
                            "id":i["id"],
                            "client_id":i["client_id"],
                            "project_id":i["project_id"],
                            "project_category":i["project_category"],
                            "time_spent":i["time_spent"],
                            "description":i["description"],
                            "created_by_id":i["created_by_id"],
                            "created_by_name":created_by_cuser.u_first_name,


                            "reporting_manager_ref_id":i["reporting_manager_ref_id"],
                            
                            "task_worked_list":i["task_worked_list"],
                            "approved_by_id":i["approved_by_id"],
                            
                            "approved_state":i["approved_state"],
                            "sort":i["sort"],
                            "applied_date":i["applied_date"],
                            "applied_date_timestamp":i["applied_date_timestamp"],
                            "approved_date_timestamp":i["approved_date_timestamp"],
                            "approved_date":i["approved_date"],
                            "approved_date_time":i["approved_date_time"],
                            "created_date_time":i["created_date_time"],
                        }
                        if i['approved_by_id']:
                            cuser_approved_data = CustomUser.objects.get(id=i['approved_by_id'])
                            dic["approved_by_name"]=cuser_approved_data.u_first_name
                        if i['reporting_manager_ref_id']:
                            cuser_reporting_manager_data = CustomUser.objects.get(id=i['reporting_manager_ref_id'])
                            dic["reporting_manager_ref_name"] = cuser_reporting_manager_data.u_first_name

                        timesheet_list.append(dic)



                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id)).count()

                    yet_to_be_approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id))
                    approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id))
                    declined_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id))
                    
                    yet_to_be_approved_hours = 0
                    approved_hours = 0
                    declined_hours = 0

                    for i in yet_to_be_approved_queryset:
                        ytb_timespent = i.time_spent
                        yet_to_be_approved_hours = yet_to_be_approved_hours + int(ytb_timespent.split('hr')[0])
                        
                    for j in approved_queryset:
                        a_timespent = j.time_spent
                        approved_hours = approved_hours + int(a_timespent.split('hr')[0])

                    for k in declined_queryset:
                        a_timespent = k.time_spent
                        declined_hours = declined_hours + int(a_timespent.split('hr')[0])



                    
                    total = (yet_to_be_approved_hours+approved_hours+declined_hours)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'request_hours':yet_to_be_approved_hours,
                            'approved_hours':approved_hours,
                            'declined_hours':declined_hours,
                            'total_hours':total,
                            'from_date':timesheet_from_date,
                            'to_date':timesheet_to_date,
                            'from_date_timestamp':fd,
                            'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(timesheet_list,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY USER ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
            else:
                if approved_state:
                    if 'search_key' in request.query_params:
                        search_key = request.query_params.get('search_key')

                        r_cuser = CustomUser.objects.filter(Q(u_first_name__icontains  = search_key))
                        r_query = Q()
                        for r_entry in r_cuser:
                            r_query = r_query | Q(created_by_id=r_entry.id)

                        print(r_query,'r_query====>')
                        if r_query:
                            queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & r_query & Q(approved_state=approved_state) ).values().order_by('-created_date_time')
                        else:
                            queryset1 = []
                    else:
                        queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(created_by_id=user_id)).values().order_by('-created_date_time')

                    for i in queryset1:
                        created_by_cuser = CustomUser.objects.get(id=i['created_by_id'])
                        
                        dic = {
                            "id":i["id"],
                            "client_id":i["client_id"],
                            "project_id":i["project_id"],
                            "project_category":i["project_category"],
                            "time_spent":i["time_spent"],
                            "description":i["description"],
                            "created_by_id":i["created_by_id"],
                            "created_by_name":created_by_cuser.u_first_name,


                            "reporting_manager_ref_id":i["reporting_manager_ref_id"],
                            
                            "task_worked_list":i["task_worked_list"],
                            "approved_by_id":i["approved_by_id"],
                    
                            "approved_state":i["approved_state"],
                            "sort":i["sort"],
                            "applied_date":i["applied_date"],
                            "applied_date_timestamp":i["applied_date_timestamp"],
                            "approved_date_timestamp":i["approved_date_timestamp"],
                            "approved_date":i["approved_date"],
                            "approved_date_time":i["approved_date_time"],
                            "created_date_time":i["created_date_time"],
                        }
                        if i['approved_by_id']:
                            cuser_approved_data = CustomUser.objects.get(id=i['approved_by_id'])
                            dic["approved_by_name"]=cuser_approved_data.u_first_name
                        if i['reporting_manager_ref_id']:
                            cuser_reporting_manager_data = CustomUser.objects.get(id=i['reporting_manager_ref_id'])
                            dic["reporting_manager_ref_name"]=cuser_reporting_manager_data.u_first_name,

                        timesheet_list.append(dic)



                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id)).count()

                    yet_to_be_approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED')& Q(created_by_id=user_id))
                    approved_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(created_by_id=user_id))
                    declined_queryset = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(created_by_id=user_id))
                    
                    yet_to_be_approved_hours = 0
                    approved_hours = 0
                    declined_hours = 0

                    for i in yet_to_be_approved_queryset:
                        ytb_timespent = i.time_spent
                        yet_to_be_approved_hours = yet_to_be_approved_hours + int(ytb_timespent.split('hr')[0])
                        
                    for j in approved_queryset:
                        a_timespent = j.time_spent
                        approved_hours = approved_hours + int(a_timespent.split('hr')[0])

                    for k in declined_queryset:
                        a_timespent = k.time_spent
                        declined_hours = declined_hours + int(a_timespent.split('hr')[0])



                    
                    total = (yet_to_be_approved_hours+approved_hours+declined_hours)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'request_hours':yet_to_be_approved_hours,
                            'approved_hours':approved_hours,
                            'declined_hours':declined_hours,
                            'total_hours':total,
                            # 'from_date':timesheet_from_date,
                            # 'to_date':timesheet_to_date,
                            # 'from_date_timestamp':fd,
                            # 'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(timesheet_list,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY USER ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
        
        if project_id:
            if approved_state:
                    fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())
                    print(fd,'from_Dateee======')
                    print(td,'To_Dateee======')
                    queryset1 = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(created_by_id=user_id) & Q(applied_date_timestamp__gte=fd) & Q(project_id=project_id)).values().order_by('-created_date_time')

                    for i in queryset1:
                        created_by_cuser = CustomUser.objects.get(id=i['created_by_id'])
                        cuser_reporting_manager_data = CustomUser.objects.get(id=i['reporting_manager_ref_id'])
                       
                        dic = {
                            "id":i["id"],
                            "client_id":i["client_id"],
                            "project_id":i["project_id"],
                            "project_category":i["project_category"],
                            "time_spent":i["time_spent"],
                            "description":i["description"],
                            "created_by_id":i["created_by_id"],
                            "created_by_name":created_by_cuser.u_first_name,


                            "reporting_manager_ref_id":i["reporting_manager_ref_id"],
                            "reporting_manager_ref_name":cuser_reporting_manager_data.u_first_name,

                            "task_worked_list":i["task_worked_list"],
                            "approved_by_id":i["approved_by_id"],
                           

                            "approved_state":i["approved_state"],
                            "sort":i["sort"],
                            "applied_date":i["applied_date"],
                            "applied_date_timestamp":i["applied_date_timestamp"],
                            "approved_date_timestamp":i["approved_date_timestamp"],
                            "approved_date":i["approved_date"],
                            "approved_date_time":i["approved_date_time"],
                            "created_date_time":i["created_date_time"],
                        }
                        if i['approved_by_id']:
                            cuser_approved_data = CustomUser.objects.get(id=i['approved_by_id'])
                            dic["approved_by_name"]=cuser_approved_data.u_first_name
                        timesheet_list.append(dic)



                    yet_to_be_approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED') & Q(project_id=project_id)).count()
                    approved_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED')& Q(project_id=project_id)).count()
                    declined_count = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED')& Q(project_id=project_id)).count()
                    total = (yet_to_be_approved_count+approved_count+declined_count)

                    all_count = {
                            'request_count':yet_to_be_approved_count,
                            'approved_count':approved_count,
                            'declined_count':declined_count,
                            'total_hours':total,
                            'from_date':timesheet_from_date,
                            'to_date':timesheet_to_date,
                            'from_date_timestamp':fd,
                            'to_date_timestamp':td
                        }
                    data_pagination = EztimeAppPagination(timesheet_list,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY PROJECT ID','timesheet_dashboard':all_count,
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
        




        all_data = TimeSheets.objects.filter(Q(organization_id=organization_id)).values().order_by('-created_date_time')
        
        data_pagination = EztimeAppPagination(all_data,page_number,data_per_page,request)

        return Response({'result':{'status':'GET ALL',
            'pagination':{
                'current_page':data_pagination[1]['current_page'],
                'number_of_pages':data_pagination[1]['number_of_pages'],
                'next_url':data_pagination[1]['next_url'],
                'previous_url':data_pagination[1]['previous_url'],
                'has_next':data_pagination[1]['has_next'],
                'has_previous':data_pagination[1]['has_previous'],
                'has_other_pages':data_pagination[1]['has_other_pages'],
            },
            'data':data_pagination[0]
            }})
    


class ApprovalTimesheetAPIView(APIView):

    def get(self,request):
        data = request.data
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
        
        organization_id = request.query_params.get("organization_id")
        approved_by_user_id = request.query_params.get("user_id")
        
        cuser = CustomUser.objects.get(id=approved_by_user_id)
        user_data = UserRole.objects.get(id=cuser.user_role_id)

        if (user_data.user_role_name).upper() == "MANAGER" or (user_data.user_role_name).upper() == "SUPER ADMIN" or (user_data.user_role_name).upper() == "ADMIN":
            if TimesheetsApprovalConfig.objects.filter(organization_id=organization_id).exists():
                t_data = TimesheetsApprovalConfig.objects.filter(organization_id=organization_id).values()
                return Response({'result':{'message':'Timesheets Approval Config Get','data':t_data}})

            else:
                return Response({
                    'error':{'message':'You organization do not have Timesheets Approval Config.',
                    'description':"Timesheets Approval Config",
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND) 
            
            
        else:
            return Response({
                    'error':{'message':'You are not authorized to perform this operation.',
                    'description':"you are not a SUPER ADMIN, MANAGER or ADMIN",
                    'status_code':status.HTTP_401_UNAUTHORIZED,
                    }},status=status.HTTP_401_UNAUTHORIZED) 
      
       
    def post(self,request):
        data = request.data
        res = CheckPermission(request)
        if res[0] == 2:
            return res[1]

        organization_id = data.get("organization_id")
        approved_by_user_id = data.get("user_id")
        approval_period = data.get("approval_period")
        grace_days_to_approve = data.get('grace_days_to_approve')
        auto_approve= data.get("auto_approve")
        active_status = data.get('active_status')

        cuser =CustomUser.objects.get(id=approved_by_user_id)
        user_data = UserRole.objects.get(id=cuser.user_role_id)

        if (user_data.user_role_name).upper() == "MANAGER" or (user_data.user_role_name).upper() == "SUPER ADMIN" or (user_data.user_role_name).upper() == "ADMIN":

            if approval_period == "DAILY":
                approval_period_in_days = 1 + int(grace_days_to_approve)
            elif approval_period == "WEEKLY":
                approval_period_in_days = 7 + int(grace_days_to_approve)
            elif approval_period == "MONTHLY":
                approval_period_in_days = 30 + int(grace_days_to_approve)
            else:
                Response({
                    'error':{'message':'approval_period value not valid',
                        'description':'We do not accept these period',
                        'hint':" DAILY , WEEKLY or MONTHLY is acceptable ",
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)

            if TimesheetsApprovalConfig.objects.filter(organization_id=organization_id).exists():
                TimesheetsApprovalConfig.objects.filter(organization_id=organization_id).update(
                    approved_by_user_id = approved_by_user_id,
                    approval_period=approval_period,
                    approval_period_in_days=approval_period_in_days,
                    grace_days_to_approve=grace_days_to_approve,
                    auto_approve=auto_approve,
                    active_status=active_status
                )
                return Response({'result':{'message':'Timesheets Approval Config Updated successfully'}})

            else:
                all_data = TimesheetsApprovalConfig.objects.create(
                        organization_id=organization_id,
                        approved_by_user_id = approved_by_user_id,
                        approval_period=approval_period,
                        approval_period_in_days=approval_period_in_days,
                        grace_days_to_approve=grace_days_to_approve,
                        auto_approve=auto_approve,
                        active_status=active_status
                    )    
            return Response({'result':{'message':'Timesheets Approval Config created successfully'}})
        else:
            return Response({
                    'error':{'message':'You are not authorized to perform this operation.',
                    'description':"you are not a MANAGER or Admin",
                    'status_code':status.HTTP_401_UNAUTHORIZED,
                    }},status=status.HTTP_401_UNAUTHORIZED) 

    def delete(self,request,pk):
        test = (0,{})
        all_values = TimesheetsApprovalConfig.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
            'error':{'message':'Record not found!',
            'status_code':status.HTTP_404_NOT_FOUND,
            }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})
    

import calendar

class DeadLineCrossedTimesheetAPIView(APIView):
    def get(self,request):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
            
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')

        organization_id= request.query_params.get('organization_id')
        user_id= request.query_params.get('user_id')
        timesheet_from_date= request.query_params.get('timesheets_from_date')
        
        cuser = CustomUser.objects.get(id=user_id)
        user_data = UserRole.objects.get(id=cuser.user_role_id)

        if (user_data.user_role_name).upper() == "MANAGER" or (user_data.user_role_name).upper() == "SUPER ADMIN" or (user_data.user_role_name).upper() == "ADMIN":
            try:
                timesheet_config_data = TimesheetsApprovalConfig.objects.get(organization_id = organization_id)

            except TimesheetsApprovalConfig.DoesNotExist:
                        return Response({
                        'error':{'message':'No record found!',
                        'hint':'Deadline Crossed depend on Timesheets Approval Config',
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)

            
            if user_id:    
                if timesheet_from_date:
                    x = timesheet_from_date.split('/')
                    if int(x[1]) == 12:
                        add = int(x[2])+1
                        print(x[0],'x[0]====>')
                        print(type(x[0]),'x[0]====>t')
                        timesheet_to_date = x[0]+'/01/'+str(add)
                    else:
                        add = int(x[1])+1
                        print(x[0],'x[0]====>')
                        print(type(x[0]),'x[0]====>t')
                        if int(add) >= 10:
                            timesheet_to_date = x[0]+'/'+str(add)+'/'+x[2]
                        else:
                            timesheet_to_date = x[0]+'/0'+str(add)+'/'+x[2]


                    fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())

                    print(fd,'from_Dateee======')
                    print(td,'To_Dateee======')
                    queryset1 = TimeSheets.objects.filter( Q(reporting_manager_ref_id=user_id) & Q(applied_date_timestamp__gte=fd)& Q(applied_date_timestamp__lt=td) & Q(approved_state="YET_TO_APPROVED")).values().order_by('-created_date_time')
                    deadline_list = []
                    for i in queryset1:
                        if (i['approved_date_timestamp'] != None) | (i['approved_date_timestamp'] != ''):
                            c_u_data = CustomUser.objects.get(id=i['created_by_id'])
                            i['created_by_name']= c_u_data.u_first_name
                            print("approved_date_timestamp===>",i['approved_date_timestamp'])
                            now = datetime.datetime.now()
                            date_object = datetime.datetime.now().strftime("%d/%m/%Y")
                            now_timestamp = time.mktime(datetime.datetime.strptime(date_object, "%d/%m/%Y").timetuple())
                            
                            from_applied_date_timestamp = float(i['applied_date_timestamp'])
                            y = i['applied_date'].split('/')
                            z = date_object.split('/')
                            
                            approval_period_in_days = timesheet_config_data.approval_period_in_days

                            final_date =  int(y[0]) + int(approval_period_in_days)
                            last_date_of_month = calendar.monthrange(int(y[2]), int(y[1]))[1]
                            print(last_date_of_month,'last_date_of_month')

                            if final_date <= last_date_of_month:
                                created_date = str(final_date)+'/'+y[1]+'/'+y[2]
                                to_applied_date_time_stamp = time.mktime(datetime.datetime.strptime(created_date, "%d/%m/%Y").timetuple())
                            else:
                                remainder = last_date_of_month - final_date
                                add = int(y[1])+1
                                created_date = str(remainder)+'/'+str(add)+'/'+y[2]
                                to_applied_date_time_stamp = time.mktime(datetime.datetime.strptime(created_date, "%d/%m/%Y").timetuple())
                            
                            if x[1] == z[1]:
                                print("this_month===>",now_timestamp,y[1])
                                if float(to_applied_date_time_stamp) <= float(now_timestamp):
                                    deadline_list.append(i)
                            else:
                                print("not_this_month===>",to_applied_date_time_stamp,y[1])
                                if float(to_applied_date_time_stamp) < float(td):
                                    deadline_list.append(i)
                                else:
                                    if float(to_applied_date_time_stamp) < float(now_timestamp):
                                        deadline_list.append(i)

                        
                    data_pagination = EztimeAppPagination(deadline_list,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY USER ID DEADLINE CROSS',
                    'note':'DEADLINE CROSS will consider today deadline also',
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
                else:
                    # fd = time.mktime(datetime.datetime.strptime(timesheet_from_date, "%d/%m/%Y").timetuple())
                    # td = time.mktime(datetime.datetime.strptime(timesheet_to_date, "%d/%m/%Y").timetuple())

                    # print(fd,'from_Dateee======')
                    # print(td,'To_Dateee======')
                    
                    queryset1 = TimeSheets.objects.filter( Q(reporting_manager_ref_id=user_id) &  Q(approved_state="YET_TO_APPROVED")).values().order_by('-created_date_time')
                    deadline_list = []
                    for i in queryset1:
                        if (i['approved_date_timestamp'] != None) | (i['approved_date_timestamp'] != ''):
                            c_u_data = CustomUser.objects.get(id=i['created_by_id'])
                            i['created_by_name']= c_u_data.u_first_name
                            print("approved_date_timestamp===>",i['approved_date_timestamp'])
                            now = datetime.datetime.now()
                            date_object = datetime.datetime.now().strftime("%d/%m/%Y")
                            now_timestamp = time.mktime(datetime.datetime.strptime(date_object, "%d/%m/%Y").timetuple())
                            
                            from_applied_date_timestamp = float(i['applied_date_timestamp'])
                            y = i['applied_date'].split('/')
                            z = date_object.split('/')
                            
                            approval_period_in_days = timesheet_config_data.approval_period_in_days

                            final_date =  int(y[0]) + int(approval_period_in_days)
                            last_date_of_month = calendar.monthrange(int(y[2]), int(y[1]))[1]
                            print(last_date_of_month,'last_date_of_month')

                            if final_date <= last_date_of_month:
                                created_date = str(final_date)+'/'+y[1]+'/'+y[2]
                                to_applied_date_time_stamp = time.mktime(datetime.datetime.strptime(created_date, "%d/%m/%Y").timetuple())
                            else:
                                remainder = last_date_of_month - final_date
                                add = int(y[1])+1
                                created_date = str(remainder)+'/'+str(add)+'/'+y[2]
                                to_applied_date_time_stamp = time.mktime(datetime.datetime.strptime(created_date, "%d/%m/%Y").timetuple())
                            
                            # if x[1] == z[1]:
                            #     print("this_month===>",now_timestamp,y[1])
                            #     if float(to_applied_date_time_stamp) <= float(now_timestamp):
                            #         deadline_list.append(i)
                            # else:
                            print("not_this_month===>",to_applied_date_time_stamp,y[1])
                            # if float(to_applied_date_time_stamp) < float(td):
                            deadline_list.append(i)
                            # else:
                            #     if float(to_applied_date_time_stamp) < float(now_timestamp):
                            #         deadline_list.append(i)

                        
                    data_pagination = EztimeAppPagination(deadline_list,page_number,data_per_page,request)
                    return Response({'result':{'status':'GET BY USER ID DEADLINE CROSS',
                    'note':'DEADLINE CROSS will consider today deadline also',
                        'pagination':{
                            'current_page':data_pagination[1]['current_page'],
                            'number_of_pages':data_pagination[1]['number_of_pages'],
                            'next_url':data_pagination[1]['next_url'],
                            'previous_url':data_pagination[1]['previous_url'],
                            'has_next':data_pagination[1]['has_next'],
                            'has_previous':data_pagination[1]['has_previous'],
                            'has_other_pages':data_pagination[1]['has_other_pages'],
                        },
                        'data':data_pagination[0]
                        }})
            
            else:
                return Response({
                'error':{'message':'Please check parameter!',
                'detail':"Mandatory fields are required",
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)

            if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
                return Response({
                    'error':{'message':'page_number or data_per_page parameter missing!',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
            
            pagination = request.query_params.get('pagination')

            if pagination == 'FALSE':
                all_data = TimeSheets.objects.all().values()
                return Response({'result':{'status':'GET all without pagination','data':all_data}})
            
        else:
            return Response({
                    'error':{'message':'You are not authorized to perform this operation.',
                    'description':"you are not a MANAGER or SUPER ADMIN",
                    'status_code':status.HTTP_401_UNAUTHORIZED,
                    }},status=status.HTTP_401_UNAUTHORIZED) 






