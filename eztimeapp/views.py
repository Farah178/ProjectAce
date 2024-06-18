from django.conf import settings
from django.http.response import JsonResponse
from rest_framework.response import Response
from requests.api import request
from django.db.models import Q
from django.contrib import auth
from django.contrib.auth import authenticate
from django.db.utils import IntegrityError
from eztimeapp.backends import *
from eztimeapp.decorator import *

from .serializers import *
import random
from .models import *
from m1.models import *
import time
import datetime
import inspect
from django.core.mail import message, send_mail, EmailMessage
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from rest_framework.views import APIView 
from rest_framework.generics import GenericAPIView
import jwt
from rest_framework import status
from django.utils.decorators import method_decorator
import re
from mimetypes import guess_extension
from .pagination import *
import base64
from django.core.exceptions import ObjectDoesNotExist

import json
import holidays
from holidays import country_holidays
import calendar
from django.views.decorators.csrf import csrf_exempt

def diffdate(valid_date):

    now_date = datetime.datetime.today().strftime("%d/%m/%Y")
    print(valid_date,'valid_date====>')
    print(now_date,'now_date====>')
    converted_to_date = datetime.datetime.fromtimestamp(int(float(valid_date)))
    d_format_convert = converted_to_date.strftime("%d/%m/%Y")
    print(d_format_convert,'d_format_convert====>')
    date1 = datetime.datetime.strptime(d_format_convert, "%d/%m/%Y")
    date2 = datetime.datetime.strptime(now_date, "%d/%m/%Y")
    
    # difference between dates in timedelta
    delta = date1 - date2
    print(delta.days,'delta.days====>')
    return delta.days


def clearnotificationcenter():
    create_notification = NotificationCenter.objects.all().delete()
    print('ALL NOTIFICATION DELETED====>notificationcenter')
    return "ALL NOTIFICATION DELETED"



def createnotification(proj_id,notify,title,remaing_date,org_ref_id):
    
    info_dic = {
        "message":title,
        "days":abs(remaing_date)
    }
    create_notification = NotificationCenter.objects.create(
        organization_id=org_ref_id,
        project_id=proj_id,
        notify=notify,
        info=info_dic
    )
    print('TASK COMPLETED===>createnotification')
    return create_notification

def conditionCheck(proj_id,remaing_date,project_name,p_status,org_ref_id):
    # print(i,'iiiiiiiiiiiii')
    if remaing_date < 7 and remaing_date > 0:
        if p_status != "Completed":
            title = str(remaing_date)+" days left to complete "+str(project_name) +" project."
            createnotification(proj_id,"ORANGE",title,remaing_date,org_ref_id)
    if remaing_date == 0:
        if p_status != "Completed":
            title = "Today is the last to complete "+str(project_name) +" project."
            createnotification(proj_id,"RED",title,remaing_date,org_ref_id)

    if remaing_date < 0:
        if p_status != "Completed":
            title = "Project " + str(project_name)+" deadline cross by "+ str(abs(remaing_date)) + " days"
            createnotification(proj_id,"RED",title,remaing_date,org_ref_id)

    print('TASK COMPLETED===>conditionCheck')
    return "DONE"

def notificationcenter():
    clearnotificationcenter()
    print("IN notificationcenter")

    project_data = Projects.objects.all().values()
    for a in project_data:
        if (a['p_closure_date'] == None) | (a['p_closure_date'] == ''):
            print('p_closure_date===> null present')
        else:
            remaing_date = diffdate(a['p_closure_date'])
            print(remaing_date)
            conditionCheck(a['id'],remaing_date,a['p_name'],a['p_status'],a['org_ref_id'])
            

    print('TASK COMPLETED===>notificationcenter')
    return "TASK COMPLETED"


class NotificationCenterApiView(APIView):
    def get(self, request):
        
        key = {'organization_id'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = request.query_params.get("organization_id")
        notificationcenter()
        all_data_list = []
        data = NotificationCenter.objects.filter(Q(organization_id=organization_id)).values()
        for i in data:
            project_data = Projects.objects.get(id=i['project_id'])
            all_data = {
                'organization_id': i['organization_id'],
                'project_id': i['project_id'],
                'notify': i['notify'],
                'info': i['info'],
                'project_data':{
                    'organization_id':project_data.org_ref_id,
                    'project_id':project_data.id,
                    'project_name':project_data.p_name,
                    'project_closure_date':project_data.p_closure_date,
                    'project_status':project_data.p_status
                }
            }
            all_data_list.append(all_data)
        return Response({'result': {'data': all_data_list}}, status=status.HTTP_200_OK)


class HolidaysapiView(APIView):
    def get(self,request):
        date = request.query_params.get('date')
        country = request.query_params.get('country')
        state = request.query_params.get('state')

        print(date,'date===>')
        date_object = datetime.datetime.strptime(date, "%d/%m/%Y")
        # now.strftime("%Y-%m-%d")
        filter_date = date_object.strftime("%Y-%m-%d")
        print(filter_date,'filter_date')

        if state:
            print("inside if")
            in_holidays = holidays.country_holidays(country, subdiv=state)  # this is a dict
            in_holidays.get(filter_date)
        else:
            print("inside else")
            in_holidays = holidays.country_holidays(country)  # this is a dict
            in_holidays.get(filter_date)
        holiday_list = []
        result = {}
        for i in in_holidays:
            print(type(i),'iiii',in_holidays[i])
            date = i.strftime("%d/%m/%Y")
            dic = {
                in_holidays[i]:date
            }
            result.update(dic)
        holiday_list.append(result)
        return Response({'message':holiday_list})

class PinApiVew(APIView):
    def get(self,request):
        all_data = Center.objects.all().order_by('sort').values()
         
        return Response({'result':{
            'all_data':all_data,
        'message': 'Table rearranged Sucessfully'
        }})  
    def post(self,request):
        data = request.data
        model = data['model']
       
        result = MySorting(model,request)
        print(result,'result====>')
        if result == "2":
            return Response({'error':{'message': 'invalid modle'}})
        elif result == "1":
            return Response({'result':{'message': 'Table rearranged Sucessfully'}})  
        else:
            return Response({'error':{'message': 'list is invalid'}})


 



class RegistrationApiVew(APIView):
    serializer_class = CustomUserTableSerializers
    queryset = CustomUser.objects.all()
    def post(self,request):
        data = request.data
        response = {}
        u_first_name = data['u_first_name']  
        u_last_name = data['u_last_name']  
        u_gender = data['u_gender']  
        u_marital_status = data['u_marital_status']  
        u_phone_no        = data['u_phone_no']
        email         = data['email']
        password      = data['password']
        u_org_code = data['org_code']
        u_designation = data['u_designation']
        organization_id = data['organization_id']
        
        # extra
        u_date_of_joining = data['u_date_of_joining']
        center_id = data['center_id']
        user_reporting_manager_ref_id = data['user_reporting_manager_ref_id']

        # people
        profile_base64  = data['profile_base64']
        prefix_suffix_id   = data['prefix_suffix_id']
        department_id      = data['department_id']
        # role_id            = data['role_id']
        user_role_id            = data['user_role_id']
        cost_center_id     = data['cost_center_id']
        tags            = data['tags']
        user_status = data['user_status']


        if data:
            if User.objects.filter(Q(username=email)|Q(email=email)).exists():
                return Response({'error':'User Already Exists'})
            else:

                create_super_user = User.objects.create_user(username=email,email=email,password=password)
                userrole = UserRole.objects.get(id=user_role_id)

                user_create = CustomUser.objects.create(
                    center_id=center_id,
                    user_role_id = user_role_id,
                    organization_id=organization_id,
                    super_user_ref_id=create_super_user.id,
                    u_email=email,
                    u_designation=u_designation,
                    u_phone_no=u_phone_no,
                    u_org_code=u_org_code,
                    u_first_name=u_first_name,
                    u_last_name=u_last_name,
                    u_gender=u_gender,
                    u_marital_status=u_marital_status,
                    u_date_of_joining=u_date_of_joining,
                    u_status= user_status
                    )
                
                people_data = People.objects.create(
                                    user_reporting_manager_ref_id = user_reporting_manager_ref_id,
                                    user_id = user_create.id,
                                    organization_id=organization_id,
                                    prefix_suffix_id = prefix_suffix_id,
                                    department_id = department_id,
                                    user_role_id = user_role_id,
                                    # role_id = role_id,
                                    cost_center_id = cost_center_id,
                                    tags = tags,
                                    )
                
                file_stored_path = '/eztime/django/site/media/photo/'
                project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
                
                if profile_base64 != '':
                    stored_path = StoreBase64ReturnPath(profile_base64, file_stored_path, project_base_url)
                    user_create.u_profile_path = stored_path
                    user_create.save()

                user_id = user_create.id
                auth_token = jwt.encode(
                            {'user_id': user_create.id, 'center_id':center_id,'username': create_super_user.username, 'email': create_super_user.email, 'mobile': user_create.u_phone_no}, str(settings.JWT_SECRET_KEY), algorithm="HS256")
                authorization = 'Bearer'+' '+auth_token
                response_result = {}
                arragned_data = RearrangeModulePermission(userrole.module_name,userrole.permissions)
                if arragned_data[0] == 2:
                    return arragned_data[1]
                
                message= 'Hi '+ u_first_name +'\n\nYour project Ace account has been created sucessfully!'
                subject= 'RE : Project Ace account created sucessfully!' 
                email = EmailMessage(subject, message, to=[email])
                email.send()
                response_result['result'] = {
                    'result': {'data': 'Register successful',
                    'user_id': user_id,
                    'organization_id':user_create.organization_id,
                    'center_id':user_create.center_id,
                    # 'role_id': people_data.role_id,
                    'user_status': user_create.u_status,
                    'manager_id':people_data.user_reporting_manager_ref_id,
                    'user_role_id': user_create.user_role_id,
                    'user_role_name': userrole.user_role_name,
                    'arragned_data':arragned_data[1],
                    'module_name': userrole.module_name,
                    'permissions': userrole.permissions,
                    'token':authorization,
                    'profile_path':user_create.u_profile_path
                    }}
                response['Authorization'] = authorization
                # response['Token-Type']      =   'Bearer'
                response['status'] = status.HTTP_200_OK

                return Response(response_result['result'], headers=response,status= status.HTTP_200_OK)
                # return Response({'result':'User Register Successfully'})
        else:
            return Response({'error':'Please fill all the details'})


class LoginView(APIView):
    serializer_class = CustomUserTableSerializers
    def post(self, request):
        response = {}
        data = request.data
        username = data.get('username')
        password = data.get('password')
        user_check = User.objects.filter(username= username)
        if user_check:
            user = auth.authenticate(username=username, password=password)
            if user:
                custom_user = User.objects.get(id=user.id)
                auth_token = jwt.encode(
                    {'user_id': user.id, 'username': user.username, 'email': user.email}, str(settings.JWT_SECRET_KEY), algorithm="HS256")
                try:
                    c_user = CustomUser.objects.get(super_user_ref=custom_user.id)
                    if c_user is not None and c_user.u_status is not None:
                        if c_user.u_status.upper() == 'INACTIVE':
                            return Response({
                                'error': {
                                    'message': "Contact admin to activate your account!",
                                    'hint': 'People database should not be deleted, Clear user and create a new one',
                                    'status_code': status.HTTP_401_UNAUTHORIZED,
                                }
                            }, status=status.HTTP_401_UNAUTHORIZED)

                    try:
                        people_data = People.objects.get(user_id=c_user.id)
                    except People.DoesNotExist:
                        return Response({
                        'error':{'message':'People does not exists!',
                        'hint':'People database should not be deleted, Clear user and create a new one',
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)
                    userrole = UserRole.objects.get(id=c_user.user_role_id)
                    
                except CustomUser.DoesNotExist:
                    return Response({
                    'error':{'message':'CustomUser does not exists!',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
               
                serializer = CustomUserTableSerializers(user)
                authorization = 'Bearer'+' '+auth_token
                response_result = {}
                arragned_data = RearrangeModulePermission(userrole.module_name,userrole.permissions)
                if arragned_data[0] == 2:
                    return arragned_data[1]

                if userrole.user_role_name == 'ADMIN':
                    manager_id = c_user.id
                else:
                    manager_id = people_data.user_reporting_manager_ref_id


                response_result['result'] = {
                    'detail': 'Login successfull',
                    'token':authorization,
                    'user_id': c_user.id,
                    'u_first_name':c_user.u_first_name,
                    'u_last_name':c_user.u_last_name,
                    'u_gender':c_user.u_gender,
                    'u_marital_status':c_user.u_marital_status,
                    'u_designation':c_user.u_designation,
                    'u_date_of_joining':c_user.u_date_of_joining,
                    'u_email':c_user.u_email,
                    'u_phone_no':c_user.u_phone_no,
                    'organization_id':c_user.organization_id,
                    'user_status': c_user.u_status,
                    'user_role_id': c_user.user_role_id,
                    'user_role_name': userrole.user_role_name,
                    'center_id':c_user.center_id,
                    'role_id': people_data.role_id,
                    'manager_id':manager_id,
                    'arragned_data':arragned_data[1],
                    'module_name': userrole.module_name,
                    'permissions': userrole.permissions,
                    'profile_path':c_user.u_profile_path,
                    'status': status.HTTP_200_OK
                    
                    }
                response['Authorization'] = authorization
                response['status'] = status.HTTP_200_OK
                # return Response(response_result['result'], headers=response,status= status.HTTP_200_OK)
            else:
                header_response = {}
                response['error'] = {'error': {
                    'detail': 'invalid emailid/password', 'status': status.HTTP_401_UNAUTHORIZED}}
                return Response(response['error'], headers=header_response,status= status.HTTP_401_UNAUTHORIZED)
            return Response(response_result, headers=response,status= status.HTTP_200_OK)
        else:
            response['error'] = {'error': {
                    'detail': 'invalid emailid/password', 'status': status.HTTP_401_UNAUTHORIZED}}
            return Response(response['error'], status= status.HTTP_401_UNAUTHORIZED)


class ForgotPasswordSendOtp(APIView):

    def post(self, request):
        data = request.data

        username = data.get('username')
        Otp = random.randint(100000, 999999)
        F_Otp = Otp
    
        
        # Get the current date and time
        now_date = datetime.datetime.today()
        print("Current date and time:", now_date)

        # Add 10 minutes to the current date and time
        future_date = now_date + datetime.timedelta(minutes=10)
        print("Future date and time (+10 minutes):", future_date)

        # Convert the future date and time to a timestamp
        timestamp = int(future_date.timestamp())
        print("Timestamp:", timestamp)

        # Convert the timestamp back to a datetime object
        converted_to_date = datetime.datetime.fromtimestamp(timestamp)
        print("Converted date from timestamp:", converted_to_date)

        if User.objects.filter(Q(username=username)).exists():
            update_otp = CustomUser.objects.filter(u_email=username).update(u_reset_otp=int(Otp),u_reset_otp_time_stamp=int(timestamp))
            print(update_otp,'update_otp')
            pass
        else:
            return Response({'error':{'message':'username doesnot exists'}},status=status.HTTP_406_NOT_ACCEPTABLE)
    
        user_check=CustomUser.objects.get(u_email=username)
        email_id=user_check.u_email
        print(email_id,'email_id')
        # if '@' in username:
        message = inspect.cleandoc('''Hi ,\n %s is your OTP to Forgot Password to your eztime account.\nThis OTP is valid for next 10 minutes,
                                \nWith Warm Regards,\nTeam EzTime,
                                ''' % (Otp))
        send_mail(
            'Greetings from EzTime', message
            ,
            'shyam@ekfrazo.in',
            [email_id],
        )
        data_dict = {}
        data_dict["OTP"] = Otp
        data_dict["timeout"] = timestamp
        return Response({'result':data_dict})
    

class OtpVerificationForgotpass(APIView):

    def post(self, request):
        data = request.data
        otp = data.get('OTP')
        email = data.get('username')
        user_check=CustomUser.objects.get(u_email=email)

        # Get the current date and time
        now_date = datetime.datetime.today()
        print("Current date and time:", now_date)

        # Add 10 minutes to the current date and time
        # future_date = now_date + datetime.timedelta(minutes=10)
        # print("Future date and time (+10 minutes):", future_date)

        # Convert the future date and time to a timestamp
        timestamp = int(now_date.timestamp())
        

        if otp==user_check.u_reset_otp and timestamp <= user_check.u_reset_otp_time_stamp:
            update_otp = CustomUser.objects.filter(u_email=email).update(u_reset_otp=None)
            return Response({'result':{'message': 'OTP matches successfully'}})
        else:
            return Response({'error':{'message': 'Invalid OTP or Timeout'}},status=status.HTTP_406_NOT_ACCEPTABLE)


class ForgotPasswordReset(APIView):

    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')
        user_check = User.objects.filter(username= username) 
        if user_check:
            user_data = User.objects.get(username= username)
            user_data.set_password(password)
            user_data.save()
            message= 'Hello!\nYour password has been updated sucessfully. '
            subject= 'Password Updated Sucessfully ' 
            email = EmailMessage(subject, message, to=[user_data.email])
            email.send()
            return Response({'result':{'message': 'Password Updated Sucessfully'}})        
        else:
            return Response({'error':{'message': 'Please Enter Valid username'}},status=status.HTTP_401_UNAUTHORIZED)


class ChangePassword(GenericAPIView):
    def post(self,request):
        data         =    request.data
        user_id        =    data.get('user_id')  
        new_password        =    data.get('new_password') 
        old_password        =    data.get('old_password') 
        print(data,'dattaaaaa')
        try:
            get_cuser = CustomUser.objects.get(id=user_id)

            check_user = User.objects.get(id=get_cuser.super_user_ref_id)
            if check_user:
                if check_user.check_password(old_password):
                    check_user.set_password(new_password)
                    check_user.save()
                    return Response({'result':'password changed successfully!'})
                else:
                    return Response({
                    'error':{'message':'incorrect old password!',
                    'status_code':status.HTTP_401_UNAUTHORIZED,
                    }},status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'error':{'message':'user does not exists!',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
                return Response({
                'error':{'message':'user does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
    

@method_decorator([AutorizationRequired], name='dispatch')
class OrganizationApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')

        if pagination == 'FALSE':
            all_data = Organization.objects.filter(~Q(org_qr_uniq_id='ProjectACE2025')).values().order_by('-id')
            org_list = []
            for i in all_data:
                org_data = CustomUser.objects.filter(Q(organization_id=i['id'])).count()
                dic ={
                    'id':i['id'],
                    'number_of_users_in_organization':org_data,
                    'org_qr_uniq_id':i['org_qr_uniq_id'],
                    'org_name':i['org_name'],
                    'org_email':i['org_email'],
                    'org_phone':i['org_phone'],
                    'org_mobile':i['org_mobile'],
                    'org_fax':i['org_fax'],
                    'org_website':i['org_website'],
                    'org_address':i['org_address'],
                    'org_city':i['org_city'],
                    'org_state':i['org_state'],
                    'org_country':i['org_country'],
                    'org_postal_code':i['org_postal_code'],
                    'org_profile_updated_status':i['org_profile_updated_status'],
                    'org_default_currency_type':i['org_default_currency_type'],
                    'org_default_timezone':i['org_default_timezone'],
                    'org_status':i['org_status'],
                    'org_subscription_plan':i['org_subscription_plan'],
                    'org_logo':i['org_logo'],
                    'org_logo_path':i['org_logo_path'],
                    'conctact_person_designation':i['conctact_person_designation'],
                    'conctact_person_name':i['conctact_person_name'],
                    'conctact_person_email':i['conctact_person_email'],
                    'conctact_person_password':i['conctact_person_password'],
                    'conctact_person_phone_number':i['conctact_person_phone_number'],
                    'sort':i['sort'],
                }
                org_list.append(dic)

            return Response({'result':{'status':'GET all without pagination','data':org_list}})

        if 'search_key' in request.query_params:
            search_key = request.query_params.get('search_key')
            all_data = Organization.objects.filter(org_name__icontains=search_key).values().order_by('-id')
            org_list = []
            for i in all_data:
                org_data = CustomUser.objects.filter(Q(organization_id=i['id'])).count()
                dic ={
                    'id':i['id'],
                    'org_qr_uniq_id':i['org_qr_uniq_id'],
                    'number_of_users_in_organization':org_data,
                    'org_name':i['org_name'],
                    'org_email':i['org_email'],
                    'org_phone':i['org_phone'],
                    'org_mobile':i['org_mobile'],
                    'org_fax':i['org_fax'],
                    'org_website':i['org_website'],
                    'org_address':i['org_address'],
                    'org_city':i['org_city'],
                    'org_state':i['org_state'],
                    'org_country':i['org_country'],
                    'org_postal_code':i['org_postal_code'],
                    'org_profile_updated_status':i['org_profile_updated_status'],
                    'org_default_currency_type':i['org_default_currency_type'],
                    'org_default_timezone':i['org_default_timezone'],
                    'org_status':i['org_status'],
                    'org_subscription_plan':i['org_subscription_plan'],
                    'org_logo':i['org_logo'],
                    'org_logo_path':i['org_logo_path'],
                    'conctact_person_designation':i['conctact_person_designation'],
                    'conctact_person_name':i['conctact_person_name'],
                    'conctact_person_email':i['conctact_person_email'],
                    'conctact_person_password':i['conctact_person_password'],
                    'conctact_person_phone_number':i['conctact_person_phone_number'],
                    'sort':i['sort'],
                }
                org_list.append(dic)

            data_pagination = EztimeAppPagination(org_list,page_number,data_per_page,request)

            return Response({'result':{'status':'GET FILTER',
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

        
        if id:
            try:
                all_data = Organization.objects.filter(id=id).values().order_by('-id')
                org_list = []
                for i in all_data:
                    org_data = CustomUser.objects.filter(Q(organization_id=i['id'])).count()
                    dic ={
                        'id':i['id'],
                        'org_qr_uniq_id':i['org_qr_uniq_id'],
                        'number_of_users_in_organization':org_data,
                        'org_name':i['org_name'],
                        'org_email':i['org_email'],
                        'org_phone':i['org_phone'],
                        'org_mobile':i['org_mobile'],
                        'org_fax':i['org_fax'],
                        'org_website':i['org_website'],
                        'org_address':i['org_address'],
                        'org_city':i['org_city'],
                        'org_state':i['org_state'],
                        'org_country':i['org_country'],
                        'org_postal_code':i['org_postal_code'],
                        'org_profile_updated_status':i['org_profile_updated_status'],
                        'org_default_currency_type':i['org_default_currency_type'],
                        'org_default_timezone':i['org_default_timezone'],
                        'org_status':i['org_status'],
                        'org_subscription_plan':i['org_subscription_plan'],
                        'org_logo':i['org_logo'],
                        'org_logo_path':i['org_logo_path'],
                        'conctact_person_designation':i['conctact_person_designation'],
                        'conctact_person_name':i['conctact_person_name'],
                        'conctact_person_email':i['conctact_person_email'],
                        'conctact_person_password':i['conctact_person_password'],
                        'conctact_person_phone_number':i['conctact_person_phone_number'],
                        'sort':i['sort'],
                    }
                    org_list.append(dic)

                return Response({'result':{'status':'GET by Id','data':org_list}})

            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = Organization.objects.filter(~Q(org_qr_uniq_id='ProjectACE2025')).values().order_by('-id')
            org_list = []
            for i in all_data:
                org_data = CustomUser.objects.filter(Q(organization_id=i['id'])).count()
                dic ={
                    'id':i['id'],
                    'org_qr_uniq_id':i['org_qr_uniq_id'],
                    'number_of_users_in_organization':org_data,
                    'org_name':i['org_name'],
                    'org_email':i['org_email'],
                    'org_phone':i['org_phone'],
                    'org_mobile':i['org_mobile'],
                    'org_fax':i['org_fax'],
                    'org_website':i['org_website'],
                    'org_address':i['org_address'],
                    'org_city':i['org_city'],
                    'org_state':i['org_state'],
                    'org_country':i['org_country'],
                    'org_postal_code':i['org_postal_code'],
                    'org_profile_updated_status':i['org_profile_updated_status'],
                    'org_default_currency_type':i['org_default_currency_type'],
                    'org_default_timezone':i['org_default_timezone'],
                    'org_status':i['org_status'],
                    'org_subscription_plan':i['org_subscription_plan'],
                    'org_logo':i['org_logo'],
                    'org_logo_path':i['org_logo_path'],
                    'conctact_person_designation':i['conctact_person_designation'],
                    'conctact_person_name':i['conctact_person_name'],
                    'conctact_person_email':i['conctact_person_email'],
                    'conctact_person_password':i['conctact_person_password'],
                    'conctact_person_phone_number':i['conctact_person_phone_number'],
                    'sort':i['sort'],
                }
                org_list.append(dic)

            data_pagination = EztimeAppPagination(org_list,page_number,data_per_page,request)

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

    def post(self,request):
        data = request.data
        # user_ref                        = data.get('user_ref_id')
        org_qr_uniq_id                  = data.get('org_qr_uniq_id')
        org_name                        = data.get('org_name')
        org_email                       = data.get('org_email')
        org_phone                       = data.get('org_phone')
        org_mobile                      = data.get('org_mobile')
        org_fax                         = data.get('org_fax')
        org_website                     = data.get('org_website')
        org_address                     = data.get('org_address')
        org_city                        = data.get('org_city')
        org_state                       = data.get('org_state')
        org_country                     = data.get('org_country')
        org_postal_code                 = data.get('org_postal_code')
        org_profile_updated_status      = data.get('org_profile_updated_status')
        org_default_currency_type       = data.get('org_default_currency_type')
        org_default_timezone            = data.get('org_default_timezone')
        org_status                      = data.get('org_status')
        org_subscription_plan           = data.get('org_subscription_plan')
        # org_logo                        = data.get('org_logo')
        # org_logo_path                   = data.get('org_logo_path')
        # org_logo_base_url               = data.get('org_logo_base_url')
        conctact_person_designation=data.get('conctact_person_designation')
        conctact_person_name=data.get('conctact_person_name')
        conctact_person_email=data.get('conctact_person_email')
        conctact_person_password=data.get('conctact_person_password')
        conctact_person_phone_number=data.get('conctact_person_phone_number')
        org_logo = data['org_logo']

        if User.objects.filter(Q(username=conctact_person_email)|Q(email=conctact_person_email)).exists():
                return Response({
                    'error':{'message':'Email already taken !',
                    'hit':'Add another email or contact super administrator',
                    'status_code':status.HTTP_400_BAD_REQUEST,
                    }},status=status.HTTP_400_BAD_REQUEST)
        else:

            base64_data = org_logo
            split_base_url_data=org_logo.split(';base64,')[1]
            imgdata1 = base64.b64decode(split_base_url_data)

            data_split = org_logo.split(';base64,')[0]
            extension_data = re.split(':|;', data_split)[1] 
            guess_extension_data = guess_extension(extension_data)

            filename1 = "/eztime/django/site/media/org_logo/"+org_name+guess_extension_data
            # filename1 = "D:/EzTime/eztimeproject/media/photo/"+name+'.png'
            fname1 = '/org_logo/'+org_name+guess_extension_data
            ss=  open(filename1, 'wb')
            print(ss)
            ss.write(imgdata1)
            ss.close()   

            if Organization.objects.filter(org_name__icontains=org_name).exists():
                return Response({
                'error':{'message':'Oraganization Name already exists!',
                'detail':"please check with Super Admin",
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)

           
            try:
                check_data = Organization.objects.create(
                # user_ref_id=user_ref,
                org_qr_uniq_id=org_qr_uniq_id,
                org_name=org_name.upper(),
                org_email=org_email,
                org_phone=org_phone,
                org_mobile=org_mobile,
                org_fax=org_fax,
                org_website=org_website,
                org_address=org_address,
                org_city=org_city,
                org_state=org_state,
                org_country=org_country,
                org_postal_code=org_postal_code,
                org_profile_updated_status=org_profile_updated_status,
                org_default_currency_type=org_default_currency_type,
                org_default_timezone=org_default_timezone,
                org_status=org_status,
                org_subscription_plan=org_subscription_plan,
                org_logo=fname1,
                # org_logo_path=org_logo_path,
                base64=base64_data,
                conctact_person_designation=conctact_person_designation,
                conctact_person_name=conctact_person_name,
                conctact_person_email=conctact_person_email,
                conctact_person_password=conctact_person_password,
                conctact_person_phone_number=conctact_person_phone_number,)
                if org_logo:
                        check_data.org_logo_path = 'https://projectaceuat.thestorywallcafe.com/media/org_logo/'+ (str(check_data.org_logo)).split('org_logo/')[1]
                        # check_data.file_attachment_path = 'http://127.0.0.1:8000/media/file_attachment/'+ (str(check_data.file_attachment)).split('file_attachment/')[1]
                        check_data.save()
                
                create_super_user = User.objects.create_user(username=conctact_person_email,email=conctact_person_email,password=conctact_person_password)

                # Create contact peron login as ADMIN
                module_name_list = ["ROLES", "REVIEW", "PEOPLE", "DEPARTMENT", "ACCOUNTS", "TIMESHEET", "LEAVE/HOLIDAY_LIST", "PROJECTS", "PROJECT_STATUS", "PROJECT_TASK_CATEGORIES", "CLIENTS", "ORGANIZATION", "INDUSTRY/SECTOR"]
                permissions_list = [{"ROLES": ["CREATE", "UPDATE", "VIEW", "DELETE"], "ROLES_ACCESSIBILITY": ["CREATE", "UPDATE", "VIEW"]}, {"REVIEW": ["VIEW", "APPROVE", "REJECT"]}, {"TAGS": ["CREATE", "UPDATE", "VIEW", "DELETE"], "PEOPLE": ["CREATE", "UPDATE", "VIEW", "DELETE"], "CENTERS": ["CREATE", "UPDATE", "VIEW", "DELETE"], "PREFIX/SUFFIX": ["CREATE", "UPDATE", "VIEW", "DELETE"], "LEAVE_MANAGEMENT": [], "CENTERS_YEAR_LIST": [], "CENTERS_HOLIDAY_LIST": []}, {"DEPARTMENT": ["CREATE", "UPDATE", "VIEW", "DELETE"]}, {"ACCOUNTS_MENU": ["VIEW"], "SUBCRIPTION_PLAN": ["VIEW"]}, {"PEOPLE_TIMESHEET": ["CREATE", "VIEW", "DELETE", "ACCEPT", "REJECT"], "DEAD_LINE_CROSSED": ["VIEW", "ACCEPT", "REJECT"], "APPROVAL_CONFIGURATION": ["VIEW", "ACCEPT", "REJECT"], "MONTH_APPROVAL_TIMESHEET": ["VIEW", "ACCEPT", "REJECT"], "TODAY_APPROVAL_TIMESHEET": ["VIEW", "ACCEPT", "REJECT"], "PEOPLE_TIMESHEET_CALENDER": ["VIEW"]}, {"MY_LEAVES": ["CREATE", "VIEW"], "LEAVE_MASTER": ["CREATE", "UPDATE", "VIEW", "DELETE"], "LEAVE_APPLICATION": ["CREATE", "VIEW", "APPROVE", "REJECT"], "OFFICE_WORKING_DAYS": ["CREATE", "VIEW"], "ADD_ON_LEAVE_REQUEST": ["CREATE", "VIEW", "REJECT"], "APPLIED/APPROVIED_LEAVES": ["CREATE", "VIEW", "DELETE", "APPROVE", "REJECT"]}, {"PROJECTS": ["CREATE", "UPDATE", "VIEW", "DELETE"], "PROJECTS_FILES": [], "PROJECTS_TASKS/CHECKLIST": []}, {"PROJECT_STATUS": [], "SUB_CATEGORIES": ["CREATE", "UPDATE", "VIEW", "DELETE"], "MAIN_CATEGORIES": ["CREATE", "UPDATE", "VIEW", "DELETE"]}, {"TASK/CHECKLIST": [], "PROJECT_TASK_CATEGORIES": ["CREATE", "UPDATE", "VIEW", "DELETE"], "CATEGORIES_FILE_TEMPLATE": [], "TASK/CHECKLIST_FILE_TEMPLATE": []}, {"CLIENTS": ["CREATE", "UPDATE", "VIEW", "DELETE"]}, {"ORGANIZATION": ["VIEW", "ADD", "EDIT", "DELETE"]}, {"INDUSTRY/SECTOR": ["CREATE", "UPDATE", "VIEW", "DELETE"]}]
                
                # userrole = UserRole.objects.get(user_role_name='ADMIN')
                # if userrole
                userrole = UserRole.objects.create(
                    user_role_name='ADMIN',
                    organization_id=check_data.id,
                    description="description",
                    priority='1',
                    role_status='Active',
                    module_name=module_name_list,
                    permissions=permissions_list,
                )

                user_create = CustomUser.objects.create(
                    user_role_id = userrole.id,
                    organization_id=check_data.id,
                    super_user_ref_id=create_super_user.id,
                    u_email=conctact_person_email,
                    u_designation=conctact_person_designation,
                    u_phone_no=conctact_person_phone_number,
                    u_first_name=conctact_person_name,
                    u_password=conctact_person_password,
                    )
                
                people_data = People.objects.create(
                                    user_id = user_create.id,
                                    organization_id=check_data.id,
                                    user_role_id = userrole.id,
                                    )
                

                return Response({'result':{'status':'Organisation Created successfully!!','message':str(conctact_person_email)+ ' got the ADMIN access to '+str(org_name)+' organisation'}})
            
            except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        # user_ref                        = data.get('user_ref_id')
        org_qr_uniq_id                  = data.get('org_qr_uniq_id')
        org_name                        = data.get('org_name')
        org_email                       = data.get('org_email')
        org_phone                       = data.get('org_phone')
        org_mobile                      = data.get('org_mobile')
        org_fax                         = data.get('org_fax')
        org_website                     = data.get('org_website')
        org_address                     = data.get('org_address')
        org_city                        = data.get('org_city')
        org_state                       = data.get('org_state')
        org_country                     = data.get('org_country')
        org_postal_code                 = data.get('org_postal_code')
        org_profile_updated_status      = data.get('org_profile_updated_status')
        org_default_currency_type       = data.get('org_default_currency_type')
        org_default_timezone            = data.get('org_default_timezone')
        org_status                      = data.get('org_status')
        org_subscription_plan           = data.get('org_subscription_plan')
        # org_logo                        = data.get('org_logo')
        # org_logo_path                   = data.get('org_logo_path')
        # org_logo_base_url               = data.get('org_logo_base_url')
        conctact_person_designation=data.get('conctact_person_designation')
        conctact_person_name=data.get('conctact_person_name')
        conctact_person_email=data.get('conctact_person_email')
        conctact_person_password=data.get('conctact_person_password')
        conctact_person_phone_number=data.get('conctact_person_phone_number')
        org_logo = data['org_logo']
        print(org_logo,'Attttttttttttttttttttt')
        result = {}
        # change password of contact person
        get_cuser = CustomUser.objects.get(u_email=conctact_person_email)
        check_user = User.objects.get(id=get_cuser.super_user_ref_id)
        if get_cuser.u_password == conctact_person_password:
            print('==')
        else:
            if check_user:
                # if check_user.check_password(get_cuser.u_password):
                check_user.set_password(conctact_person_password)
                check_user.save()
                CustomUser.objects.filter(id=get_cuser.id).update(u_password=conctact_person_password)
                result['note']='password updated successfully'
        # ===============================

        if Organization.objects.filter(~Q(id=pk) & Q(org_name__iexact=org_name)).exists():
            return Response({
            'error':{'message':'Oraganization Name already exists!',
            'detail':"please check with Super Admin",
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

        if org_logo == '':
            print('in if nulll looopp')
            try:
                Organization.objects.filter(id=pk).update(
                        # user_ref_id=user_ref,
                        org_qr_uniq_id=org_qr_uniq_id,
                        org_name=org_name.upper(),
                        org_email=org_email,
                        org_phone=org_phone,
                        org_mobile=org_mobile,
                        org_fax=org_fax,
                        org_website=org_website,
                        org_address=org_address,
                        org_city=org_city,
                        org_state=org_state,
                        org_country=org_country,
                        org_postal_code=org_postal_code,
                        org_profile_updated_status=org_profile_updated_status,
                        org_default_currency_type=org_default_currency_type,
                        org_default_timezone=org_default_timezone,
                        org_status=org_status,
                        org_subscription_plan=org_subscription_plan,
                        # org_logo=fname1,
                        # org_logo_path=org_logo_path,
                        # base64=base64_data,
                        conctact_person_designation=conctact_person_designation,
                        conctact_person_name=conctact_person_name,
                        # conctact_person_email=conctact_person_email,
                        conctact_person_password=conctact_person_password,
                        conctact_person_phone_number=conctact_person_phone_number,
                )
                return Response({'result':{'status':'Updated','message':result}})
            except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
                
        base64_data=org_logo
        split_base_url_data=org_logo.split(';base64,')[1]
        imgdata1 = base64.b64decode(split_base_url_data)
        data_split = org_logo.split(';base64,')[0]
        extension_data = re.split(':|;', data_split)[1] 
        guess_extension_data = guess_extension(extension_data)
        filename1 = "/eztime/django/site/media/org_logo/"+org_name+guess_extension_data
        # filename1 = "D:/EzTime/eztimeproject/media/photo/"+name+'.png'
        fname1 = '/org_logo/'+org_name+guess_extension_data
        ss=  open(filename1, 'wb')
        print(ss)
        ss.write(imgdata1)
        ss.close()   
        try:
            Organization.objects.filter(id=pk).update(
                # user_ref_id=user_ref,
                org_qr_uniq_id=org_qr_uniq_id,
                org_name=org_name,
                org_email=org_email,
                org_phone=org_phone,
                org_mobile=org_mobile,
                org_fax=org_fax,
                org_website=org_website,
                org_address=org_address,
                org_city=org_city,
                org_state=org_state,
                org_country=org_country,
                org_postal_code=org_postal_code,
                org_profile_updated_status=org_profile_updated_status,
                org_default_currency_type=org_default_currency_type,
                org_default_timezone=org_default_timezone,
                org_status=org_status,
                org_subscription_plan=org_subscription_plan,
                org_logo=fname1,
                # org_logo_path=org_logo_path,
                base64=base64_data,
                conctact_person_designation=conctact_person_designation,
            conctact_person_name=conctact_person_name,
            # conctact_person_email=conctact_person_email,
            conctact_person_password=conctact_person_password,
            conctact_person_phone_number=conctact_person_phone_number,
                )
            check_data = Organization.objects.get(id=pk)
            if org_logo:
                    check_data.org_logo_path = 'https://projectaceuat.thestorywallcafe.com/media/org_logo/'+ (str(check_data.org_logo)).split('org_logo/')[1]
                    # check_data.file_attachment_path = 'http://127.0.0.1:8000/media/file_attachment/'+ (str(check_data.file_attachment)).split('file_attachment/')[1]
                    check_data.save()
            return Response({'result':{'status':'Updated','message':result}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
    

    def delete(self,request,pk):
        # CheckAuthData(request)
        test = (0,{})
        try:
            people_data = People.objects.get(organization_id=pk)
            get_c_user = CustomUser.objects.get(id=people_data.user_id)
            
            people = People.objects.filter(id=pk).delete()
            people = CustomUser.objects.filter(id=people_data.user_id).delete()
            super_user_id = User.objects.filter(id=get_c_user.super_user_ref_id).delete()
            all_values = Organization.objects.filter(id=pk).delete()
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'Organization and people related are deleted successfully'}})
        

# @method_decorator([AutorizationRequired], name='dispatch')
# class TypeOfIndustriesApiView(APIView):
#     def get(self,request):
        
#         id = request.query_params.get('id')
#         pagination = request.query_params.get('pagination')
        # if pagination == 'FALSE':
        #     all_data = TypeOfIndustries.objects.all().values().order_by('-id')
        #     return Response({'result':{'status':'GET all without pagination','data':all_data}})

        # if id:
#             try:
#                 all_data = TypeOfIndustries.objects.filter(id=id).values().order_by('-id')
#                 return Response({'result':{'status':'GET by Id','data':all_data}})
#             except Organization.DoesNotExist:
#                 return Response({
#                 'error':{'message':'Id does not exists!',
#                 'status_code':status.HTTP_404_NOT_FOUND,
#                 }},status=status.HTTP_404_NOT_FOUND)
#         else:
#             all_data = TypeOfIndustries.objects.all().values().order_by('-id')
#             return Response({'result':{'status':'GET','data':all_data}})
@method_decorator([AutorizationRequired], name='dispatch')
class TypeOfIndustriesApiView(APIView):
    
    def get(self,request):
        key = {'org_ref_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        org_ref_id = request.query_params.get('org_ref_id')
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        
    
        
        if id:
            try:
                all_data = TypeOfIndustries.objects.filter(Q(id=id) & Q(org_ref_id=org_ref_id)).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            pagination = request.query_params.get('pagination')
            if pagination == 'FALSE':
                all_data = TypeOfIndustries.objects.filter(Q(org_ref_id=org_ref_id) & ~Q(toi_status='Inactive')).values().order_by('-id')
                return Response({'result':{'status':'GET all without pagination','data':all_data}})

            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
               
                all_data = TypeOfIndustries.objects.filter(Q(org_ref_id=org_ref_id) & (Q(toi_title__icontains  = search_key)|Q(toi_description__icontains  = search_key)|Q(toi_status__icontains  = search_key)|Q(toi_c_date__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = TypeOfIndustries.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')

            # all_data = TypeOfIndustries.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data
        toi_title               = data.get('toi_title')
        toi_description         = data.get('toi_description')
        toi_status              = data.get('toi_status')
        toi_type                = data.get('toi_type')
        key = {'org_ref_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        org_ref_id                 = data.get('org_ref_id')

        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:

            if TypeOfIndustries.objects.filter(Q(toi_title__iexact =toi_title) & Q(org_ref_id=org_ref_id)).exists():
                return Response({
                    'error': {'message': 'Type Of Industry name already exists!',
                            'detail': 'Type Of Industry name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)

            else:
                    TypeOfIndustries.objects.create(
                    org_ref_id=org_ref_id,
                    toi_title=toi_title,
                    toi_description=toi_description,
                    toi_status=toi_status,
                    toi_type=toi_type
                                                )
                    posts = TypeOfIndustries.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')
                    paginator = Paginator(posts,10)
                    try:
                        page_obj = paginator.get_page(selected_page_no)
                    except PageNotAnInteger:
                        page_obj = paginator.page(1)
                    except EmptyPage:
                        page_obj = paginator.page(paginator.num_pages)
                    return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
       
        toi_title               = data.get('toi_title')
        toi_description         = data.get('toi_description')
        toi_status              = data.get('toi_status')
        toi_type                = data.get('toi_type')
        key = {'org_ref_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        org_ref_id                 = data.get('org_ref_id')
        
        try:
            if TypeOfIndustries.objects.filter(Q(org_ref_id=org_ref_id) & ~Q(id=pk) & Q(toi_title__iexact=toi_title)).exists():
                return Response({
                    'error': {'message': 'Type Of Industry name already exists!',
                            'detail': 'Type Of Industry name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)
            else:
                TypeOfIndustries.objects.filter(id=pk).update(
                    org_ref_id=org_ref_id,
                    toi_title=toi_title,
                    toi_description=toi_description,
                    toi_status=toi_status,
                    toi_type=toi_type
                    )
                return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = TypeOfIndustries.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class ClientsApiView(APIView):
    def get(self,request):
        key = {'org_ref_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        
        org_ref_id = request.query_params.get('org_ref_id')

        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        client_list = []

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = Clients.objects.filter(Q(org_ref_id=org_ref_id)).values().order_by('-id')

        elif id:
            try:
                all_data = Clients.objects.filter(Q(id=id) & Q(org_ref_id=org_ref_id)).values().order_by('-id')
            except Clients.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
               
                all_data = Clients.objects.filter(Q(org_ref_id=org_ref_id) & (Q(c_name__icontains  = search_key)|Q(c_code__icontains  = search_key)|Q(c_contact_person__icontains  = search_key)|Q(c_satus__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = Clients.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')

            
        for i in all_data:
                toi_data = TypeOfIndustries.objects.get(id=i['toi_ref_id'])
                dic = {
                    "id":i['id'],
                    "org_ref_id":i['org_ref_id'],
                    "user_ref_id":i['user_ref_id'],
                    "toi_ref_id":i['toi_ref_id'],
                    "toi_ref_name":toi_data.toi_title,
                    "c_name":i['c_name'],
                    "c_code":i['c_code'],
                    "c_address":i['c_address'],
                    "c_type":i['c_type'],
                    "c_contact_person":i['c_contact_person'],
                    "c_contact_person_email_id":i['c_contact_person_email_id'],
                    "c_contact_person_phone_no":i['c_contact_person_phone_no'],
                    "c_satus":i['c_satus'],
                    "c_c_timestamp":i['c_c_timestamp'],
                    "c_m_timestamp":i['c_m_timestamp'],
                    "project":i['project'],
                    "sort":i['sort'],
                }
                client_list.append(dic)

        if pagination == 'FALSE':
            return Response({'result':{'status':'GET all without pagination','data':client_list}})
        elif id:     
            return Response({'result':{'status':'GET by Id','data':client_list}})
        else:
            data_pagination = EztimeAppPagination(client_list,page_number,data_per_page,request)
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


    def post(self,request):
        data = request.data
        
        user_ref                    = data.get('user_ref_id')
        toi_ref                     = data.get('toi_ref_id')
        c_name                      = data.get('c_name')
        c_code                      = data.get('c_code')
        c_address                   = data.get('c_address')
        c_type                      = data.get('c_type')
        c_contact_person            = data.get('c_contact_person')
        c_contact_person_email_id   = data.get('c_contact_person_email_id')
        c_contact_person_phone_no   = data.get('c_contact_person_phone_no')
        c_satus                     = data.get('c_satus')

        key = {'org_ref_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        org_ref_id = data.get('org_ref_id')

        project = data.get('project')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)        
        try:
            if Clients.objects.filter(Q(c_name__iexact =c_name) & Q(org_ref_id=org_ref_id)).exists():
                return Response({
                    'error': {'message': 'Client name already exists!',
                            'detail': 'Client name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)
            else:

                    Clients.objects.create(
                        org_ref_id=org_ref_id,
                        user_ref_id=user_ref,
                        toi_ref_id=toi_ref,
                        c_name=c_name,
                        c_code=c_code,
                        c_address=c_address,
                        c_type=c_type,
                        c_contact_person=c_contact_person,
                        c_contact_person_email_id=c_contact_person_email_id,
                        c_contact_person_phone_no=c_contact_person_phone_no,
                        c_satus=c_satus,
                        project=project
                                        )
                    posts = Clients.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')
                    paginator = Paginator(posts,10)
                    try:
                        page_obj = paginator.get_page(selected_page_no)
                    except PageNotAnInteger:
                        page_obj = paginator.page(1)
                    except EmptyPage:
                        page_obj = paginator.page(paginator.num_pages)
                    return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
       
        user_ref                    = data.get('user_ref_id')
        toi_ref                     = data.get('toi_ref_id')
        c_name                      = data.get('c_name')
        c_code                      = data.get('c_code')
        c_address                   = data.get('c_address')
        c_type                      = data.get('c_type')
        c_contact_person            = data.get('c_contact_person')
        c_contact_person_email_id   = data.get('c_contact_person_email_id')
        c_contact_person_phone_no   = data.get('c_contact_person_phone_no')
        c_satus                     = data.get('c_satus')
        project=data.get('project')

        key = {'org_ref_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        org_ref_id = data.get('org_ref_id')
        
        try:

            if Clients.objects.filter(Q(org_ref_id=org_ref_id) & ~Q(id=pk) & Q(c_name__iexact=c_name)).exists():
                return Response({
                    'error': {'message': 'Client name already exists!',
                            'detail': 'Client name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)

            else:
                Clients.objects.filter(Q(org_ref_id=org_ref_id) & Q(id=pk)).update(
                    org_ref_id=org_ref_id,
                    user_ref_id=user_ref,
                    toi_ref_id=toi_ref,
                    c_name=c_name,
                    c_code=c_code,
                    c_address=c_address,
                    c_type=c_type,
                    c_contact_person=c_contact_person,
                    c_contact_person_email_id=c_contact_person_email_id,
                    c_contact_person_phone_no=c_contact_person_phone_no,
                    c_satus=c_satus,
                    project=project
                                    )
                return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = Clients.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class OrgPeopleGroupView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = OrgPeopleGroup.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = OrgPeopleGroup.objects.filter(id=id).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = OrgPeopleGroup.objects.all().values().order_by('-id')
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


    def post(self,request):
        
        data = request.data
        user_ref            = data.get('user_ref_id')
        org_ref             = data.get('org_ref_id')
        opg_group_name      = data.get('opg_group_name')
        opg_status          = data.get('opg_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            OrgPeopleGroup.objects.create(
                user_ref_id=user_ref,
                org_ref_id=org_ref,
                opg_group_name=opg_group_name,
                opg_status=opg_status
            )
            posts = OrgPeopleGroup.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        
        data = request.data
        user_ref            = data.get('user_ref_id')
        org_ref             = data.get('org_ref_id')
        opg_group_name      = data.get('opg_group_name')
        opg_status          = data.get('opg_status')
        try:
            OrgPeopleGroup.objects.filter(id=pk).update(
                user_ref_id=user_ref,
                org_ref_id=org_ref,
                opg_group_name=opg_group_name,
                opg_status=opg_status
            )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = OrgPeopleGroup.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

# from .pagination import MyPagination

@method_decorator([authorization_required], name='dispatch')
class OrganizationDepartmentView(APIView):
    # pagination_class = MyPagination
    # serializer_class = OrganizationDepartmentSerializer



    def get(self,request):
        id = request.query_params.get('id')
        key = {'org_ref_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        org_ref_id = request.query_params.get('org_ref_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')
        
        if id:
            try:
                all_data = OrganizationDepartment.objects.filter(Q(id=id) & Q(org_ref_id=org_ref_id)).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            if pagination == 'FALSE':
                all_data = OrganizationDepartment.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')
                return Response({'result':{'status':'GET all without pagination','data':all_data}})

            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
               
                all_data = OrganizationDepartment.objects.filter(Q(org_ref_id=org_ref_id) & (Q(od_name__icontains  = search_key)|Q(od_status__icontains  = search_key)|Q(od_c_date__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = OrganizationDepartment.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')

            # all_data = OrganizationDepartment.objects.all().values().order_by('-id')
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

        
    def post(self,request):
        data = request.data
        
        od_added_by_ref_user    = data.get('od_added_by_ref_user_id')
        od_name                 = data.get('od_name')
        od_status               = data.get('od_status')

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        org_ref_id  = data.get('organization_id')
       
        try:
            if OrganizationDepartment.objects.filter(Q(od_name__iexact=od_name) & Q(org_ref_id=org_ref_id)).exists():
                return Response({'error': {'message':'Department with the same name already exists'}}, status=status.HTTP_400_BAD_REQUEST)
            else:
                OrganizationDepartment.objects.create(org_ref_id=org_ref_id,
                                                    od_added_by_ref_user_id=od_added_by_ref_user,
                                                    od_name=od_name,
                                                    od_status=od_status)

                
                return Response({'result':{'status':'Created'}})

        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            
            

    def put(self,request,pk):
        data = request.data
        # org_ref                 = data.get('org_ref_id')
        od_added_by_ref_user    = data.get('od_added_by_ref_user_id')
        od_name                 = data.get('od_name')
        od_status               = data.get('od_status')
       
        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        org_ref_id  = data.get('organization_id')

        try:
            if OrganizationDepartment.objects.filter(~Q(id=pk) & Q(od_name__iexact=od_name) & Q(org_ref_id=org_ref_id)).exists():
                return Response({'error': {'message':'Department with the same name already exists'}}, status=status.HTTP_400_BAD_REQUEST)
            else:    
                OrganizationDepartment.objects.filter(id=pk).update(
                    # org_ref_id=org_ref,
                    od_added_by_ref_user_id=od_added_by_ref_user,
                    od_name=od_name,
                    od_status=od_status
                                                    )
                return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):

        test = (0,{}) 
        all_values = OrganizationDepartment.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class ClientsDMS(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ClientsDMS.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = ClientsDMS.objects.filter(id=id).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = ClientsDms.objects.all().values().order_by('-id')
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
            

    def post(self,request):
        data = request.data
        ref_org             =data.get('ref_org_id')
        cdms_added_ref_user =data.get('cdms_added_ref_user_id')
        c_ref               =data.get('c_ref_id')
        cdms_filename       =data.get('cdms_filename')
        cdms_file_path      =data.get('cdms_file_path')
        cdms_base_url       =data.get('cdms_base_url')
        cdms_file_ref_name  =data.get('cdms_file_ref_name')
        cdms_status         =data.get('cdms_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            ClientsDms.objects.create(
                ref_org_id=ref_org,
                cdms_added_ref_user_id=cdms_added_ref_user,
                c_ref_id=c_ref,
                cdms_filename=cdms_filename,
                cdms_file_path=cdms_file_path,
                cdms_base_url=cdms_base_url,
                cdms_file_ref_name=cdms_file_ref_name,
                cdms_status=cdms_status
                )
            posts = ClientsDms.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        ref_org             =data.get('ref_org_id')
        cdms_added_ref_user =data.get('cdms_added_ref_user_id')
        c_ref               =data.get('c_ref_id')
        cdms_filename       =data.get('cdms_filename')
        cdms_file_path      =data.get('cdms_file_path')
        cdms_base_url       =data.get('cdms_base_url')
        cdms_file_ref_name  =data.get('cdms_file_ref_name')
        cdms_status         =data.get('cdms_status')
        try:
            ClientsDms.objects.filter(id=pk).update(ref_org_id=ref_org,
                                                                cdms_added_ref_user_id=cdms_added_ref_user,
                                                                c_ref_id=c_ref,
                                                                cdms_filename=cdms_filename,
                                                                cdms_file_path=cdms_file_path,
                                                                cdms_base_url=cdms_base_url,
                                                                cdms_file_ref_name=cdms_file_ref_name,
                                                                cdms_status=cdms_status)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = ClientsDMS.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class OrganizationCostCentersView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = OrganizationCostCenters.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = OrganizationCostCenters.objects.filter(id=id).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = OrganizationCostCenters.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data
        org_ref                 = data.get('org_ref_id')
        occ_added_by_ref_user   = data.get('occ_added_by_ref_user_id')
        occ_cost_center_name    = data.get('occ_cost_center_name')
        occ_leave_mgmt_status   = data.get('occ_leave_mgmt_status')
        occ_currency_type       = data.get('occ_currency_type')
        occ_status              = data.get('occ_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            OrganizationCostCenters.objects.create(org_ref_id=org_ref,
                                                    occ_added_by_ref_user_id=occ_added_by_ref_user,
                                                    occ_cost_center_name=occ_cost_center_name,
                                                    occ_leave_mgmt_status=occ_leave_mgmt_status,
                                                    occ_currency_type=occ_currency_type,
                                                    occ_status=occ_status)
            posts = OrganizationCostCenters.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        org_ref                 = data.get('org_ref_id')
        occ_added_by_ref_user   = data.get('occ_added_by_ref_user_id')
        occ_cost_center_name    = data.get('occ_cost_center_name')
        occ_leave_mgmt_status   = data.get('occ_leave_mgmt_status')
        occ_currency_type       = data.get('occ_currency_type')
        occ_status              = data.get('occ_status')
        try:
            OrganizationCostCenters.objects.filter(id=pk).update(org_ref_id=org_ref,
                                                    occ_added_by_ref_user_id=occ_added_by_ref_user,
                                                    occ_cost_center_name=occ_cost_center_name,
                                                    occ_leave_mgmt_status=occ_leave_mgmt_status,
                                                    occ_currency_type=occ_currency_type,
                                                    occ_status=occ_status)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = OrganizationCostCenters.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class ClientsOtherContactDetailsView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ClientsOtherContactDetails.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = ClientsOtherContactDetails.objects.filter(id=id).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = ClientsOtherContactDetails.objects.all().values().order_by('-id')
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
            

    def post(self,request):
        data = request.data
        c_ref                       = data.get('c_ref_id')
        org_ref                     = data.get('org_ref_id')
        cocd_added_by_ref_user      = data.get('cocd_added_by_ref_user_id')
        cocd_name                   = data.get('cocd_name')
        cocd_phone                  = data.get('cocd_phone')
        cocd_email                  = data.get('cocd_email')
        cocd_satus                  = data.get('cocd_satus')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            ClientsOtherContactDetails.objects.create(c_ref_id=c_ref,
                                                    org_ref_id=org_ref,
                                                    cocd_added_by_ref_user_id=cocd_added_by_ref_user,
                                                    cocd_name=cocd_name,
                                                    cocd_phone=cocd_phone,
                                                    cocd_email=cocd_email,
                                                    cocd_satus=cocd_satus)
            posts = ClientsOtherContactDetails.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        c_ref                       = data.get('c_ref_id')
        org_ref                     = data.get('org_ref_id')
        cocd_added_by_ref_user      = data.get('cocd_added_by_ref_user_id')
        cocd_name                   = data.get('cocd_name')
        cocd_phone                  = data.get('cocd_phone')
        cocd_email                  = data.get('cocd_email')
        cocd_satus                  = data.get('cocd_satus')
        try:
            ClientsOtherContactDetails.objects.filter(id=pk).update(c_ref_id=c_ref,
                                                    org_ref_id=org_ref,
                                                    cocd_added_by_ref_user_id=cocd_added_by_ref_user,
                                                    cocd_name=cocd_name,
                                                    cocd_phone=cocd_phone,
                                                    cocd_email=cocd_email,
                                                    cocd_satus=cocd_satus)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
                

    def delete(self,request,pk):
        test = (0,{})
        all_values = ClientsOtherContactDetails.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class OrganizationRolesView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = OrganizationRoles.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = OrganizationRoles.objects.filter(id=id).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = OrganizationRoles.objects.all().order_by('sort').values()
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

    def post(self,request):
        data = request.data
        org_ref = data.get('org_ref_id')
        or_added_by_ref_user= data.get('or_added_by_ref_user_id')
        or_name= data.get('or_name')
        or_description= data.get('or_description')
        or_priority= data.get('or_priority')
        or_status= data.get('or_status')
        or_type= data.get('or_type')
        or_permission= data.get('or_permission')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            org_data = OrganizationRoles.objects.create(org_ref_id=org_ref,
                                            or_added_by_ref_user_id=or_added_by_ref_user,
                                            or_name=or_name,
                                            or_description=or_description,
                                            or_priority=or_priority,
                                            or_status=or_status,
                                            or_type=or_type,
                                            or_permission=or_permission)
            data = OrganizationRoles.objects.filter(id=org_data.id).update(sort=org_data.id)
            posts = OrganizationRoles.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        org_ref = data.get('org_ref_id')
        or_added_by_ref_user= data.get('or_added_by_ref_user_id')
        or_name= data.get('or_name')
        or_description= data.get('or_description')
        or_priority= data.get('or_priority')
        or_status= data.get('or_status')
        or_type= data.get('or_type')
        or_permission= data.get('or_permission')
        try:
            OrganizationRoles.objects.filter(id=pk).update(org_ref_id=org_ref,
                                                            or_added_by_ref_user_id=or_added_by_ref_user,
                                                            or_name=or_name,
                                                            or_description=or_description,
                                                            or_priority=or_priority,
                                                            or_status=or_status,
                                                            or_type=or_type,
                                                            or_permission=or_permission)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = OrganizationRoles.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})
# ! ------------------ project---------------
def convert_task_list_string(task_list):
    task_list_string = ''
    for u in task_list:
        if 'task_name' in u:
            if task_list_string == '':
                task_list_string = str(task_list_string) + str(u['task_name'] )
            else:
                task_list_string = str(task_list_string) +','+ str(u['task_name'] )
    return task_list_string

def convert_tag_list_string(tag_list):
    task_list_string = ''
    for u in tag_list:
        if 'tag_name' in u:
            if task_list_string == '':
                task_list_string = str(task_list_string) + str(u['tag_name'] )
            else:
                task_list_string = str(task_list_string) +','+ str(u['tag_name'] )
    return task_list_string





@method_decorator([AutorizationRequired], name='dispatch')
class ProjectsAPIView(APIView):
    serializer_class = ProjectsSerializer
    
    def get_queryset(self):
        organization_id = self.request.query_params.get('organization_id')
        queryset = Projects.objects.select_related(
            'c_ref', 'reporting_manager_ref', 'approve_manager_ref'
        ).filter(org_ref_id=organization_id).order_by('-id')
        return queryset

    def get(self, request, *args, **kwargs):
        

        key = {'organization_id'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = request.query_params.get('organization_id')

        if 'client_id' in request.query_params.keys():
            client_id = request.query_params.get('client_id')
            try:
                # all_data = Projects.objects.filter(Q(org_ref_id=organization_id) & Q(c_ref_id=client_id)).values().order_by('-id')
                # project_list =[]
                # for i in all_data:
                #     cuser_data = CustomUser.objects.get(id=i['reporting_manager_ref_id'])
                #     approver_data = CustomUser.objects.get(id=i['approve_manager_ref_id'])
                #     client_data = Clients.objects.get(id=i['c_ref_id'])
                #     task_list_converted = convert_task_list_string(i['project_related_task_list'])
                
                #     dic = {
                #         'id':i['id'],
                #         'org_ref_id':i['org_ref_id'],
                #         'user_ref_id':i['user_ref_id'],
                #         'c_ref_id':i['c_ref_id'],
                #         'client_name':client_data.c_name,
                #         'people_ref_list':i['people_ref_list'],
                #         'opg_ref_id':i['opg_ref_id'],
                #         'reporting_manager_ref_id':i['reporting_manager_ref_id'],
                #         'approve_manager_ref_id':i['approve_manager_ref_id'],

                #         'approver_manager_first_name':approver_data.u_first_name,
                #         'approver_manager_last_name':approver_data.u_last_name,
                #         'approver_manager_gender':approver_data.u_gender,
                #         'approver_manager_designation':approver_data.u_designation,
                #         'approver_manager_email':approver_data.u_email,
                #         'approver_manager_phone_no':approver_data.u_phone_no,

                #         'pc_ref_id':i['pc_ref_id'],
                #         'p_description':i['p_description'],
                #         'p_code':i['p_code'],
                #         'p_name':i['p_name'],
                #         'p_people_type':i['p_people_type'],
                #         'p_start_date':i['p_start_date'],
                #         'p_closure_date':i['p_closure_date'],
                #         'p_estimated_hours':i['p_estimated_hours'],
                #         'p_estimated_cost':i['p_estimated_cost'],
                #         'p_task_checklist_status':i['p_task_checklist_status'],
                #         'p_status':i['p_status'],
                #         'p_activation_status':i['p_activation_status'],
                #         'task_project_category_list':i['task_project_category_list'],
                #         'project_related_task_list':i['project_related_task_list'],
                #         'project_related_task_list_converted':task_list_converted,
                #         'p_c_date':i['p_c_date'],
                #         'sort':i['sort'],

                #         'reporting_manager_first_name':cuser_data.u_first_name,
                #         'reporting_manager_last_name':cuser_data.u_last_name,
                #         'reporting_manager_gender':cuser_data.u_gender,
                #         'reporting_manager_designation':cuser_data.u_designation,
                #         'reporting_manager_email':cuser_data.u_email,
                #         'reporting_manager_phone_no':cuser_data.u_phone_no,
                #     }
                #     if i['p_status'] == "Open":
                #         dic['p_status_color'] = 'orange'
                #     if i['p_status'] == "Pending":
                #         dic['p_status_color'] = 'red'
                #     if i['p_status'] == "Completed":
                #         dic['p_status_color'] = 'green'   

                #     project_list.append(dic) 

                # return Response({'result':{'status':'GET by client_id','data':project_list}})

                queryset = self.get_queryset()
                if not queryset.exists():
                    return Response({
                        'error': {
                            'message': 'Id does not exist!',
                            'status_code': status.HTTP_404_NOT_FOUND,
                        }
                    }, status=status.HTTP_404_NOT_FOUND)

                serializer = self.serializer_class(queryset, many=True)  # Serialize the queryset
                return Response({'result': {'status': 'GET by client_id', 'data': serializer.data}})

            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        
        key = {'page_number','data_per_page','pagination'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')
        
        if pagination == 'FALSE':
            all_data = Projects.objects.filter(Q(org_ref_id=organization_id)).values().order_by('-id')
            project_list =[]
            for i in all_data:
                cuser_data = CustomUser.objects.get(id=i['reporting_manager_ref_id'])
                approver_data = CustomUser.objects.get(id=i['approve_manager_ref_id'])
                client_data = Clients.objects.get(id=i['c_ref_id'])
                dic = {
                    'id':i['id'],
                    'org_ref_id':i['org_ref_id'],
                    'user_ref_id':i['user_ref_id'],
                    'c_ref_id':i['c_ref_id'],
                    'client_name':client_data.c_name,
                    'people_ref_list':i['people_ref_list'],
                    'opg_ref_id':i['opg_ref_id'],
                    'reporting_manager_ref_id':i['reporting_manager_ref_id'],
                    'approve_manager_ref_id':i['approve_manager_ref_id'],

                    'approver_manager_first_name':approver_data.u_first_name,
                    'approver_manager_last_name':approver_data.u_last_name,
                    'approver_manager_gender':approver_data.u_gender,
                    'approver_manager_designation':approver_data.u_designation,
                    'approver_manager_email':approver_data.u_email,
                    'approver_manager_phone_no':approver_data.u_phone_no,

                    'pc_ref_id':i['pc_ref_id'],
                    'p_description':i['p_description'],
                    'p_code':i['p_code'],
                    'p_name':i['p_name'],
                    'p_people_type':i['p_people_type'],
                    'p_start_date':i['p_start_date'],
                    'p_closure_date':i['p_closure_date'],
                    'p_estimated_hours':i['p_estimated_hours'],
                    'p_estimated_cost':i['p_estimated_cost'],
                    'p_task_checklist_status':i['p_task_checklist_status'],
                    'p_status':i['p_status'],
                    'p_activation_status':i['p_activation_status'],
                    'task_project_category_list':i['task_project_category_list'],
                    'project_related_task_list':i['project_related_task_list'],
                    'p_c_date':i['p_c_date'],
                    'sort':i['sort'],

                    'reporting_manager_first_name':cuser_data.u_first_name,
                    'reporting_manager_last_name':cuser_data.u_last_name,
                    'reporting_manager_gender':cuser_data.u_gender,
                    'reporting_manager_designation':cuser_data.u_designation,
                    'reporting_manager_email':cuser_data.u_email,
                    'reporting_manager_phone_no':cuser_data.u_phone_no,
                }
                if i['p_status'] == "Open":
                    dic['p_status_color'] = 'orange'
                if i['p_status'] == "Pending":
                    dic['p_status_color'] = 'red'
                if i['p_status'] == "Completed":
                    dic['p_status_color'] = 'green'   
                if i['p_status'] == "inprogress":
                    dic['p_status_color'] = 'purple'   
                project_list.append(dic) 

            return Response({'result':{'status':'GET all without pagination','data':project_list}})
        
        if 'id' in request.query_params.keys():
            id = request.query_params.get('id')

            try:
                all_data = Projects.objects.filter(Q(org_ref_id=organization_id) & Q(id=id)).values().order_by('-id')
                project_list =[]
                for i in all_data:
                    cuser_data = CustomUser.objects.get(id=i['reporting_manager_ref_id'])
                    approver_data = CustomUser.objects.get(id=i['approve_manager_ref_id'])
                    client_data = Clients.objects.get(id=i['c_ref_id'])
                    task_list_converted = convert_task_list_string(i['project_related_task_list'])
                
                    dic = {
                        'id':i['id'],
                        'org_ref_id':i['org_ref_id'],
                        'user_ref_id':i['user_ref_id'],
                        'c_ref_id':i['c_ref_id'],
                        'client_name':client_data.c_name,
                        'people_ref_list':i['people_ref_list'],
                        'opg_ref_id':i['opg_ref_id'],
                        'reporting_manager_ref_id':i['reporting_manager_ref_id'],
                        'approve_manager_ref_id':i['approve_manager_ref_id'],

                        'approver_manager_first_name':approver_data.u_first_name,
                        'approver_manager_last_name':approver_data.u_last_name,
                        'approver_manager_gender':approver_data.u_gender,
                        'approver_manager_designation':approver_data.u_designation,
                        'approver_manager_email':approver_data.u_email,
                        'approver_manager_phone_no':approver_data.u_phone_no,

                        'pc_ref_id':i['pc_ref_id'],
                        'p_description':i['p_description'],
                        'p_code':i['p_code'],
                        'p_name':i['p_name'],
                        'p_people_type':i['p_people_type'],
                        'p_start_date':i['p_start_date'],
                        'p_closure_date':i['p_closure_date'],
                        'p_estimated_hours':i['p_estimated_hours'],
                        'p_estimated_cost':i['p_estimated_cost'],
                        'p_task_checklist_status':i['p_task_checklist_status'],
                        'p_status':i['p_status'],
                        'p_activation_status':i['p_activation_status'],
                        'task_project_category_list':i['task_project_category_list'],
                        'project_related_task_list':i['project_related_task_list'],
                        'project_related_task_list_converted':task_list_converted,
                        'p_c_date':i['p_c_date'],
                        'sort':i['sort'],

                        'reporting_manager_first_name':cuser_data.u_first_name,
                        'reporting_manager_last_name':cuser_data.u_last_name,
                        'reporting_manager_gender':cuser_data.u_gender,
                        'reporting_manager_designation':cuser_data.u_designation,
                        'reporting_manager_email':cuser_data.u_email,
                        'reporting_manager_phone_no':cuser_data.u_phone_no,
                    }
                    if i['p_status'] == "Open":
                        dic['p_status_color'] = 'orange'
                    if i['p_status'] == "Pending":
                        dic['p_status_color'] = 'red'
                    if i['p_status'] == "Completed":
                        dic['p_status_color'] = 'green'   
                    if i['p_status'] == "inprogress":
                        dic['p_status_color'] = 'purple'   
                    project_list.append(dic) 

                return Response({'result':{'status':'GET by Id','data':project_list}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)  
        
        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
                user_id = request.query_params.get('user_id')

                r_cuser = CustomUser.objects.filter(Q(u_first_name__icontains  = search_key))
                r_query = Q()
                for r_entry in r_cuser:
                    r_query = r_query | Q(reporting_manager_ref_id=r_entry.id)

                a_cuser = CustomUser.objects.filter(Q(u_first_name__icontains  = search_key))
                a_query = Q()
                for a_entry in a_cuser:
                    a_query = a_query | Q(approve_manager_ref_id=a_entry.id)
                
                b_cuser = CustomUser.objects.filter(Q(u_first_name__icontains  = search_key))
                b_query = Q()
                for b_entry in b_cuser:
                    b_query = b_query | Q(reporting_manager_ref_id=b_entry.id)

                c_cuser = Clients.objects.filter(Q(c_name__icontains  = search_key))
                c_query = Q()
                for c_entry in c_cuser:
                    c_query = c_query | Q(c_ref_id=c_entry.id)

                all_data = Projects.objects.filter(Q(org_ref_id=organization_id) & Q(people_ref_list__contains=[{"id": int(user_id)}]) & (r_query | a_query | b_query | c_query | Q(p_name__icontains  = search_key)|Q(p_status__icontains  = search_key))).values().order_by('-id')

            
            else:
                all_data = Projects.objects.filter(Q(org_ref_id=organization_id)).values().order_by('-id')

            project_list = []
            for i in all_data:
                cuser_data = CustomUser.objects.get(id=i['reporting_manager_ref_id'])
                approver_data = CustomUser.objects.get(id=i['approve_manager_ref_id'])
                client_data = Clients.objects.get(id=i['c_ref_id'])
            
                task_list_converted = convert_task_list_string(i['project_related_task_list'])

                dic = {
                    'id':i['id'],
                    'org_ref_id':i['org_ref_id'],
                    'user_ref_id':i['user_ref_id'],
                    'c_ref_id':i['c_ref_id'],
                    'client_name':client_data.c_name,
                    'people_ref_list':i['people_ref_list'],
                    'opg_ref_id':i['opg_ref_id'],
                    'reporting_manager_ref_id':i['reporting_manager_ref_id'],
                    'approve_manager_ref_id':i['approve_manager_ref_id'],

                    'approver_manager_first_name':approver_data.u_first_name,
                    'approver_manager_last_name':approver_data.u_last_name,
                    'approver_manager_gender':approver_data.u_gender,
                    'approver_manager_designation':approver_data.u_designation,
                    'approver_manager_email':approver_data.u_email,
                    'approver_manager_phone_no':approver_data.u_phone_no,

                    'pc_ref_id':i['pc_ref_id'],
                    'p_description':i['p_description'],
                    'p_code':i['p_code'],
                    'p_name':i['p_name'],
                    'p_people_type':i['p_people_type'],
                    'p_start_date':i['p_start_date'],
                    'p_closure_date':i['p_closure_date'],
                    'p_estimated_hours':i['p_estimated_hours'],
                    'p_estimated_cost':i['p_estimated_cost'],
                    'p_task_checklist_status':i['p_task_checklist_status'],
                    'p_status':i['p_status'],
                    'p_activation_status':i['p_activation_status'],
                    'task_project_category_list':i['task_project_category_list'],
                    'project_related_task_list':i['project_related_task_list'],
                    'project_related_task_list_converted':task_list_converted,
                    'p_c_date':i['p_c_date'],
                    'sort':i['sort'],

                    'reporting_manager_first_name':cuser_data.u_first_name,
                    'reporting_manager_last_name':cuser_data.u_last_name,
                    'reporting_manager_gender':cuser_data.u_gender,
                    'reporting_manager_designation':cuser_data.u_designation,
                    'reporting_manager_email':cuser_data.u_email,
                    'reporting_manager_phone_no':cuser_data.u_phone_no,
                }
                if i['p_status'] == "Open":
                    dic['p_status_color'] = 'orange'
                if i['p_status'] == "Pending":
                    dic['p_status_color'] = 'red'
                if i['p_status'] == "Completed":
                    dic['p_status_color'] = 'green'   
                if i['p_status'] == "inprogress":
                    dic['p_status_color'] = 'purple'   
                project_list.append(dic) 

            data_pagination = EztimeAppPagination(project_list,page_number,data_per_page,request)

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

    def post(self,request):
        data = request.data
        
        user_ref                 = data['user_ref_id']
        reporting_manager_ref    = data['reporting_manager_ref_id']
        approve_manager_ref      = data['approve_manager_ref_id']
        opg_ref                  = data['opg_ref_id']
        c_ref                    = data['c_ref_id']
        p_code                   = data['p_code']
        p_name                   = data['p_name']
        p_people_type            = data['p_people_type']
        people_ref               = data['people_ref_list']
        p_description            = data['p_description']
        psd             = data['p_start_date']
        pcd           = data['p_closure_date']
        p_estimated_hours        = data['p_estimated_hours']
        p_estimated_cost         = data['p_estimated_cost']
        pc_ref                   = data['pc_ref_id']
        p_task_checklist_status  = data['p_task_checklist_status']
        p_status                 = data['p_status']
        p_activation_status      = data['p_activation_status']

        task_project_category_list = data['task_project_category_list']
        project_related_task_list   = data['project_related_task_list']

        key = {'org_ref_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        org_ref  = data['org_ref_id']

        p_start_date = time.mktime(datetime.datetime.strptime(psd, "%d/%m/%Y").timetuple())
        p_closure_date = time.mktime(datetime.datetime.strptime(pcd, "%d/%m/%Y").timetuple())
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            if Projects.objects.filter(Q(p_name__exact=p_name) & Q(org_ref_id=org_ref)).exists():
                return Response({'error': {'message':'Project with the same name already exists',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }}, status=status.HTTP_400_BAD_REQUEST)

            Projects.objects.create(
                project_related_task_list=project_related_task_list,
                task_project_category_list=task_project_category_list,
                p_code=p_code,
                org_ref_id   =   org_ref,
                opg_ref_id   =opg_ref,
                user_ref_id  =   user_ref,
                c_ref_id  =   c_ref,
                reporting_manager_ref_id =reporting_manager_ref,
                approve_manager_ref_id   =approve_manager_ref,
                pc_ref_id   =pc_ref ,
                p_name  =   p_name,
                p_people_type =p_people_type,
                people_ref_list       =people_ref,
                p_description     =p_description,
                p_start_date     =p_start_date,
                p_closure_date         =p_closure_date,
                p_estimated_hours =p_estimated_hours,
                p_estimated_cost   =p_estimated_cost,
                p_task_checklist_status =p_task_checklist_status,
                p_status =p_status,
                p_activation_status =p_activation_status
                )
            posts = Projects.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def put(self,request,pk):
        data = request.data
        # org_ref                  = data['org_ref_id']
        user_ref                 = data['user_ref_id']
        reporting_manager_ref    = data['reporting_manager_ref_id']
        approve_manager_ref      = data['approve_manager_ref_id']
        opg_ref                  = data['opg_ref_id']
        c_ref                    = data['c_ref_id']
        p_code                   = data['p_code']
        p_name                   = data['p_name']
        p_people_type            = data['p_people_type']
        people_ref               = data['people_ref_list']
        p_description            = data['p_description']
        psd             = data['p_start_date']
        pcd           = data['p_closure_date']
        p_estimated_hours        = data['p_estimated_hours']
        p_estimated_cost         = data['p_estimated_cost']
        pc_ref                   = data['pc_ref_id']
        p_task_checklist_status  = data['p_task_checklist_status']
        p_status                 = data['p_status']
        p_activation_status      = data['p_activation_status']

        
        task_project_category_list = data['task_project_category_list']
        project_related_task_list   = data['project_related_task_list']


        key = {'org_ref_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        org_ref  = data['org_ref_id']


        p_start_date = time.mktime(datetime.datetime.strptime(psd, "%d/%m/%Y").timetuple())
        p_closure_date = time.mktime(datetime.datetime.strptime(pcd, "%d/%m/%Y").timetuple())
        try:
            if Projects.objects.filter(Q(org_ref_id=org_ref) & ~Q(id=pk) & Q(p_name__exact=p_name)).exists():
                return Response({'error': {'message':'Project with the same name already exists',
                'status_code':status.HTTP_404_NOT_FOUND,
                }}, status=status.HTTP_400_BAD_REQUEST)
                        
            Projects.objects.filter(id=pk).update(
                                                project_related_task_list=project_related_task_list,

                                                task_project_category_list=task_project_category_list,
                                                p_code=p_code,
                                                # org_ref_id              =   org_ref,
                                                opg_ref_id             =opg_ref,
                                                user_ref_id             =   user_ref,
                                                c_ref_id                =   c_ref,
                                                reporting_manager_ref_id =reporting_manager_ref,
                                                approve_manager_ref_id        =approve_manager_ref,
                                                pc_ref_id                  =pc_ref ,
                                                p_name                  =   p_name,
                                                p_people_type          =p_people_type,
                                                people_ref_list             =people_ref,
                                                p_description          =p_description,
                                                p_start_date           =p_start_date,
                                                p_closure_date         =p_closure_date,
                                                p_estimated_hours      =p_estimated_hours,
                                                p_estimated_cost        =p_estimated_cost,
                                                p_task_checklist_status      =p_task_checklist_status,
                                                p_status                    =p_status,
                                                p_activation_status           =p_activation_status
                                            )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = Projects.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class TaskProjectCategoriesApiView(APIView):
    def get(self,request):
        key = {'org_ref_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        org_ref_id = request.query_params.get('org_ref_id')
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')
        # if pagination == 'FALSE':
        #     all_data = TaskProjectCategories.objects.all().values().order_by('-id')
        #     return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = TaskProjectCategories.objects.filter(Q(id=id) & Q(org_ref_id=org_ref_id)).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except TaskProjectCategories.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        elif pagination == 'FALSE':
            all_data = TaskProjectCategories.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
             
                all_data = TaskProjectCategories.objects.filter(Q(org_ref_id=org_ref_id) & (Q(tpc_name__icontains  = search_key)|Q(tpc_status__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = TaskProjectCategories.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')

            # all_data = TaskProjectCategories.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data
        tpc_name                  = data['tpc_name']
        file_templates_list       = data['file_templates_list']
        task_list                  = data['task_list']

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = data['organization_id']

     
        if len(file_templates_list) > 0:
            try:
                if TaskProjectCategories.objects.filter(Q(tpc_name__exact=tpc_name) & Q(org_ref_id=organization_id)).exists():
                    return Response({'error': {'message':'Task project category with the same name already exists',
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }}, status=status.HTTP_400_BAD_REQUEST)


                check_data = TaskProjectCategories.objects.create(
                    tpc_name = tpc_name,
                    org_ref_id=organization_id,
                    task_list = task_list,
                    tpc_status= "PENDING"
                    )

                file_stored_path = '/eztime/django/site/media/file_attachment/'
                project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
                temp_list = []
                for i in file_templates_list:
                    print(i['file_base_64'],'file_base_64')
                    if i['file_base_64'] != '':
                        stored_path = StoreBase64ReturnPath(i['file_base_64'], file_stored_path, project_base_url)
                        print(stored_path,'stored_path===>')
                        temp_dic = {
                            'file_template_name':i['file_template_name'],
                            'file_path':stored_path
                        }
                        temp_list.append(temp_dic)
                final_dic = {
                    'tpc_name':tpc_name,
                    'file_templates_list':temp_list
                }
                check_data.file_templates_list  = final_dic
                check_data.save()
                return Response({'result':{'status':'Created'}})
            
            except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'error':{'message':'At least you should have one file template',
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
                


    def put(self,request,pk):
        data = request.data
        print('pk===>',pk)

        if (data.get("tpc_status") is None):
            tpc_name                  = data['tpc_name']
            file_templates_list       = data['file_templates_list']
            task_list                  = data['task_list']

            key = {'organization_id'}
            check_result, error_response = CheckDataKey(request, key)
            if check_result == 2:
                return error_response
            organization_id = data['organization_id']

            if len(file_templates_list) > 0:
                try:
                    if TaskProjectCategories.objects.filter(Q(tpc_name__exact=tpc_name) & ~Q(id=pk) & Q(org_ref_id=organization_id)).exists():
                        return Response({'error': {'message':'Task project category with the same name already exists',
                            'status_code':status.HTTP_404_NOT_FOUND,
                            }}, status=status.HTTP_400_BAD_REQUEST)


                    check_data = TaskProjectCategories.objects.filter(id=pk).update(
                        tpc_name = tpc_name,
                        task_list = task_list,
                        )
                    print("======")
                    file_stored_path = '/eztime/django/site/media/file_attachment/'
                    project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
                    temp_list = []
                    for i in file_templates_list:
                        print(i['file_base_64'],'file_base_64')
                        if i['file_base_64'] != '':
                            print('')
                            stored_path = StoreBase64ReturnPath(i['file_base_64'], file_stored_path, project_base_url)
                            temp_dic = {
                                'file_template_name':i['file_template_name'],
                                'file_path':stored_path
                            }
                            temp_list.append(temp_dic)
                    final_dic = {
                        'tpc_name':tpc_name,
                        'file_templates_list':temp_list
                    }
                    check_data1 = TaskProjectCategories.objects.get(id=pk)
                    check_data1.file_templates_list  = final_dic
                    check_data1.save()
                    return Response({'result':{'status':'Updated'}})
                
                except IntegrityError as e:
                    error_message = e.args
                    return Response({
                    'error':{'message':'DB error!',
                    'detail':error_message,
                    'status_code':status.HTTP_400_BAD_REQUEST,
                    }},status=status.HTTP_400_BAD_REQUEST)
                
            else:
                return Response({
                    'error':{'message':'At least you should have one file template',
                    'status_code':status.HTTP_400_BAD_REQUEST,
                    }},status=status.HTTP_400_BAD_REQUEST)

        else:
            tpc_status = data['tpc_status']
            check_data = TaskProjectCategories.objects.filter(id=pk).update(
                        tpc_status = tpc_status,
                        )       
            return Response({'result':{'status':'TaskProjectCategories status updated!'}})

    def delete(self,request,pk):
        test = (0,{})
        all_values = TaskProjectCategories.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class ProjectCategoriesFilesTemplatesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ProjectCategoriesFilesTemplates.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = ProjectCategoriesFilesTemplates.objects.filter(id=id).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = ProjectCategoriesFilesTemplates.objects.all().values().order_by('-id')
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




    def post(self,request):
        data = request.data
        org_ref                 = data.get('org_ref_id')
        pcft_added_by_ref_user  = data.get('pcft_added_by_ref_user_id')
        ref_pc                  = data.get('ref_pc_id')
        pcft_name               = data.get('pcft_name')
        pcft_filename           = data.get('pcft_filename')
        pcft_file_path          = data.get('pcft_file_path')
        pcft_file_base_url      = data.get('pcft_file_base_url')
        pcft_status             = data.get('pcft_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            ProjectCategoriesFilesTemplates.objects.create(org_ref_id=org_ref ,
                                                            pcft_added_by_ref_user_id=pcft_added_by_ref_user,
                                                            ref_pc_id=ref_pc,
                                                            pcft_name=pcft_name ,
                                                            pcft_filename=pcft_filename,
                                                            pcft_file_path=pcft_file_path,
                                                            pcft_file_base_url=pcft_file_base_url,
                                                            pcft_status=pcft_status
                                                            )
            posts = ProjectCategoriesFilesTemplates.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        org_ref                 = data.get('org_ref_id')
        pcft_added_by_ref_user  = data.get('pcft_added_by_ref_user_id')
        ref_pc                  = data.get('ref_pc_id')
        pcft_name               = data.get('pcft_name')
        pcft_filename           = data.get('pcft_filename')
        pcft_file_path          = data.get('pcft_file_path')
        pcft_file_base_url      = data.get('pcft_file_base_url')
        pcft_status             = data.get('pcft_status')
        try:
            ProjectCategoriesFilesTemplates.objects.filter(id=pk).update(org_ref_id=org_ref ,
                                                            pcft_added_by_ref_user_id=pcft_added_by_ref_user,
                                                            ref_pc_id=ref_pc,
                                                            pcft_name=pcft_name ,
                                                            pcft_filename=pcft_filename,
                                                            pcft_file_path=pcft_file_path,
                                                            pcft_file_base_url=pcft_file_base_url,
                                                            pcft_status=pcft_status
                                                            )

            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = ProjectCategoriesFilesTemplates.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class ProjectStatusMainCategoryApiView(APIView):
    def get(self,request):
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
            all_data = ProjectStatusMainCategory.objects.filter(organization_id=organization_id).values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            try:
                all_data = ProjectStatusMainCategory.objects.filter(Q(id=id) & Q(organization_id=organization_id)).values().order_by('-id')
                return Response({'result':{'status':'GET by Id','data':all_data}})
            except Organization.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
            
                all_data = ProjectStatusMainCategory.objects.filter(Q(organization_id=organization_id) & Q(psmc_name__icontains  = search_key)|Q(psmc_color_code__icontains  = search_key)).values().order_by('-id')
            else:
                all_data = ProjectStatusMainCategory.objects.filter(organization_id=organization_id).values().order_by('-id')

            # all_data = ProjectStatusMainCategory.objects.all().values().order_by('-id')
            
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




    def post(self,request):
        data = request.data
        psmc_name                = data.get('psmc_name')
        psmc_status              = data.get('psmc_status')
        psmc_color_code          = data.get('psmc_color_code')

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = data.get('organization_id')

        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            if ProjectStatusMainCategory.objects.filter(Q(psmc_name__iexact =psmc_name) & Q(organization_id=organization_id)).exists():
                return Response({
                    'error': {'message': 'Project Status Main Category already exists!',
                            'detail': 'Project Status Main Category name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)
            else:
                ProjectStatusMainCategory.objects.create(psmc_name=psmc_name,
                                                        psmc_status =psmc_status ,
                                                        psmc_color_code=psmc_color_code,organization_id=organization_id
                                                    )
                posts = ProjectStatusMainCategory.objects.filter(organization_id=organization_id).values().order_by('-id')
                paginator = Paginator(posts,10)
                try:
                    page_obj = paginator.get_page(selected_page_no)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)
                return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
                
            

    def put(self,request,pk):
        data = request.data
        psmc_name                = data.get('psmc_name')
        psmc_status              = data.get('psmc_status')
        psmc_color_code          = data.get('psmc_color_code')
        try:
            if ProjectStatusMainCategory.objects.filter(~Q(id=pk) & Q(psmc_name__iexact=psmc_name)).exists():
                return Response({
                    'error': {'message': 'Project Status Main Category already exists!',
                            'detail': 'Project Status Main Category cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)

            else:
                ProjectStatusMainCategory.objects.filter(id=pk).update(psmc_name=psmc_name,
                                                        psmc_status =psmc_status ,
                                                        psmc_color_code=psmc_color_code
                                                    )
                return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = ProjectStatusMainCategory.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class ProjectHistoryApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ProjectHistory.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = ProjectHistory.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = ProjectHistory.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data                     
        p_ref                           =data.get('p_ref_id')          
        org_ref                         =data.get('org_ref_id')    
        ph_people_ref_user              =data.get('ph_people_ref_user_id')             
        ph_added_by_ref_user            =data.get('ph_added_by_ref_user_id') 
        c_ref                           =data.get('c_ref_id')
        ph_reporting_manager_ref_user   =data.get('ph_reporting_manager_ref_user_id')               
        ph_approve_manager_ref_user     =data.get('ph_approve_manager_ref_user_id')
        ph_code                         =data.get('ph_code')                
        ph_name                         =data.get('ph_name')    
        ph_people_type                  =data.get('ph_people_type')          
        opg_ref                         =data.get('opg_ref_id')  
        ph_description                  =data.get('ph_description')           
        # ph_start_date                   =data.get('ph_start_date')          
        ph_closure_date                 =data.get('ph_closure_date')           
        ph_estimated_hours              =data.get('ph_estimated_hours')              
        ph_estimated_cost               =data.get('ph_estimated_cost')              
        pc_ref                          =data.get('pc_ref_id')  
        ph_task_checklist_status        =data.get('ph_task_checklist_status')               
        ph_status                       =data.get('ph_status')  
        ph_activation_status            =data.get('ph_activation_status')              
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            ProjectHistory.objects.create(
                                        p_ref_id=p_ref,
                                        org_ref_id=org_ref,
                                        ph_people_ref_user_id=ph_people_ref_user,
                                        ph_added_by_ref_user=ph_added_by_ref_user,
                                        c_ref_id=c_ref,
                                        opg_ref_id=opg_ref,
                                        ph_reporting_manager_ref_user_id=ph_reporting_manager_ref_user,
                                        ph_approve_manager_ref_user_id=ph_approve_manager_ref_user,
                                        pc_ref_id=pc_ref,
                                        ph_code=ph_code,
                                        ph_name=ph_name,
                                        ph_people_type=ph_people_type,
                                        ph_description=ph_description,
                                        # ph_start_date=ph_start_date,
                                        ph_closure_date=ph_closure_date,
                                        ph_estimated_hours=ph_estimated_hours,
                                        ph_estimated_cost=ph_estimated_cost,
                                        ph_task_checklist_status=ph_task_checklist_status,
                                        ph_status =ph_status ,
                                        ph_activation_status=ph_activation_status
                                        )
            posts = ProjectHistory.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data                     
        p_ref                           =data.get('p_ref_id')          
        org_ref                         =data.get('org_ref_id')    
        ph_people_ref_user              =data.get('ph_people_ref_user_id')             
        ph_added_by_ref_user            =data.get('ph_added_by_ref_user_id') 
        c_ref                           =data.get('c_ref_id')
        ph_reporting_manager_ref_user   =data.get('ph_reporting_manager_ref_user_id')               
        ph_approve_manager_ref_user     =data.get('ph_approve_manager_ref_user_id')
        ph_code                         =data.get('ph_code')                
        ph_name                         =data.get('ph_name')    
        ph_people_type                  =data.get('ph_people_type')          
        opg_ref                         =data.get('opg_ref_id')  
        ph_description                  =data.get('ph_description')           
        # ph_start_date                   =data.get('ph_start_date')          
        ph_closure_date                 =data.get('ph_closure_date')           
        ph_estimated_hours              =data.get('ph_estimated_hours')              
        ph_estimated_cost               =data.get('ph_estimated_cost')              
        pc_ref                          =data.get('pc_ref_id')  
        ph_task_checklist_status        =data.get('ph_task_checklist_status')               
        ph_status                       =data.get('ph_status')  
        ph_activation_status            =data.get('ph_activation_status')              
        try:
            ProjectHistory.objects.filter(id=pk).update(p_ref_id=p_ref,
                                        org_ref_id=org_ref,
                                        ph_people_ref_user_id=ph_people_ref_user,
                                        ph_added_by_ref_user=ph_added_by_ref_user,
                                        c_ref_id=c_ref,
                                        opg_ref_id=opg_ref,
                                        ph_reporting_manager_ref_user_id=ph_reporting_manager_ref_user,
                                        ph_approve_manager_ref_user_id=ph_approve_manager_ref_user,
                                        pc_ref_id=pc_ref,
                                        ph_code=ph_code,
                                        ph_name=ph_name,
                                        ph_people_type=ph_people_type,
                                        ph_description=ph_description,
                                        # ph_start_date=ph_start_date,
                                        ph_closure_date=ph_closure_date,
                                        ph_estimated_hours=ph_estimated_hours,
                                        ph_estimated_cost=ph_estimated_cost,
                                        ph_task_checklist_status=ph_task_checklist_status,
                                        ph_status =ph_status ,
                                        ph_activation_status=ph_activation_status
                                    )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = ProjectHistory.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class ProjectStatusSubCategoryApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        key = {'org_ref_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        org_ref_id = request.query_params.get('org_ref_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
    
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ProjectStatusSubCategory.objects.filter(org_ref_id=org_ref_id).values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            
            k = ProjectStatusSubCategory.objects.get(id=id)
            if not k:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

           
            data =  ProjectStatusMainCategory.objects.get(id=k.psmc_ref_id)
            dic = {
                "id":k.id,
                "psmc_ref_id":k.psmc_ref_id,
                "psmc_name":data.psmc_name,
                "color":data.psmc_color_code,
                "org_ref_id":k.org_ref_id,
                "pssc_added_by_ref_user_id":k.pssc_added_by_ref_user_id,
                "pssc_name":k.pssc_name,
                "pssc_status":k.pssc_status,
                "pssc_c_date":k.pssc_c_date,
                "pssc_m_date":k.pssc_m_date,
                "sort":k.sort,
            }
            
        
            return Response({'result':{'status':'GET by Id','data':dic}})
        else:
            main_list = []
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
                
                pmain = ProjectStatusMainCategory.objects.filter(Q(org_ref_id=org_ref_id) & Q(psmc_color_code__icontains  = search_key) | Q(psmc_name__icontains  = search_key))
                query = Q()
                for entry in pmain:
                    query = query | Q(psmc_ref_id=entry.id)

                all_data = ProjectStatusSubCategory.objects.filter(Q(org_ref_id=org_ref_id) & query | Q(pssc_name__icontains  = search_key)|Q(pssc_status__icontains  = search_key))

            else:
                all_data = ProjectStatusSubCategory.objects.filter(org_ref_id=org_ref_id)


            
            for k in all_data:
                data =  ProjectStatusMainCategory.objects.get(id=k.psmc_ref_id)
                dic = {
                    "id":k.id,
                    "psmc_ref_id":k.psmc_ref_id,
                    "psmc_name":data.psmc_name,
                    "color":data.psmc_color_code,
                    "org_ref_id":k.org_ref_id,
                    "pssc_added_by_ref_user_id":k.pssc_added_by_ref_user_id,
                    "pssc_name":k.pssc_name,
                    "pssc_status":k.pssc_status,
                    "pssc_c_date":k.pssc_c_date,
                    "pssc_m_date":k.pssc_m_date,
                    "sort":k.sort,
                }
                main_list.append(dic)
            data_pagination = EztimeAppPagination(main_list,page_number,data_per_page,request)

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
            

    def post(self,request):
        data = request.data
        psmc_ref_id= data.get('psmc_ref_id')
        org_ref_id= data.get('org_ref_id')
        pssc_added_by_ref_user_id= data.get('pssc_added_by_ref_user_id')
        pssc_name= data.get('pssc_name')
        pssc_status= data.get('pssc_status')
        color= data.get('color')
        sort= data.get('sort')
        # psmc_ref                     =data.get('psmc_ref_id')                               
        # org_ref                      =data.get('org_ref_id') 
        # pssc_added_by_ref_user       =data.get('pssc_added_by_ref_user_id')              
        # pssc_name                    =data.get('pssc_name')                
        # pssc_status                  =data.get('pssc_status')  
        # color = data.get('color')
        key = {'org_ref_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            if ProjectStatusSubCategory.objects.filter(Q(pssc_name__iexact =pssc_name)  & Q(org_ref_id=org_ref_id)).exists():
                return Response({
                    'error': {'message': 'Project Status Sub Category name already exists!',
                            'detail': 'Project Status Sub Category name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)
            else:

                ProjectStatusSubCategory.objects.create(psmc_ref_id=psmc_ref_id,
                                                            org_ref_id=org_ref_id,
                                                            pssc_added_by_ref_user_id=pssc_added_by_ref_user_id,
                                                            pssc_name=pssc_name,
                                                            pssc_status=pssc_status,
                                                            color=color,
                                                            sort=sort,)
                posts = ProjectStatusSubCategory.objects.filter(org_reff_id=org_ref_id).values().order_by('-id')
                paginator = Paginator(posts,10)
                try:
                    page_obj = paginator.get_page(selected_page_no)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)
                return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        psmc_ref_id= data.get('psmc_ref_id')
        org_ref_id= data.get('org_ref_id')
        pssc_added_by_ref_user_id= data.get('pssc_added_by_ref_user_id')
        pssc_name= data.get('pssc_name')
        pssc_status= data.get('pssc_status')
        color= data.get('color')
        sort= data.get('sort')
        try:
            if ProjectStatusSubCategory.objects.filter(~Q(id=pk) & Q(pssc_name__iexact=pssc_name)).exists():
                return Response({
                    'error': {'message': 'Project Status Sub Category name already exists!',
                            'detail': 'Project Status Sub Category name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)


            else:
                    ProjectStatusSubCategory.objects.filter(id=pk).update(psmc_ref_id=psmc_ref_id,
                                                            org_ref_id=org_ref_id,
                                                            pssc_added_by_ref_user_id=pssc_added_by_ref_user_id,
                                                            pssc_name=pssc_name,
                                                            pssc_status=pssc_status,
                                                            color=color,
                                                            sort=sort,
                                    )
                    return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})   
        all_values = ProjectStatusSubCategory.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class ProjectFilesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ProjectFiles.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = ProjectFiles.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = ProjectFiles.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        org_ref                     =data.get('org_ref_id') 
        pf_added_ref_user           =data.get('pf_added_ref_user_id')              
        p_ref                       =data.get('p_ref_id')                
        pf_filename                 =data.get('pf_filename')  
        pf_file_path                =data.get('pf_file_path')  
        pf_base_url                 =data.get('pf_base_url')    
        pf_status                   =data.get('pf_status')    
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            ProjectFiles.objects.create(org_ref_id=org_ref,
                                        pf_added_ref_user_id=pf_added_ref_user,
                                        p_ref_id=p_ref,
                                        pf_filename=pf_filename,
                                        pf_file_path=pf_file_path,
                                        pf_base_url=pf_base_url,
                                        pf_status=pf_status
                                )
            posts = ProjectFiles.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            


    def put(self,request,pk):
        data = request.data
        org_ref                     =data.get('org_ref_id') 
        pf_added_ref_user           =data.get('pf_added_ref_user_id')              
        p_ref                       =data.get('p_ref_id')                
        pf_filename                 =data.get('pf_filename')  
        pf_file_path                =data.get('pf_file_path')  
        pf_base_url                 =data.get('pf_base_url')    
        pf_status                   =data.get('pf_status')    
        try:
            ProjectFiles.objects.filter(id=pk).update(org_ref_id=org_ref,
                                        pf_added_ref_user_id=pf_added_ref_user,
                                        p_ref_id=p_ref,
                                        pf_filename=pf_filename,
                                        pf_file_path=pf_file_path,
                                        pf_base_url=pf_base_url,
                                        pf_status=pf_status
                                    )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e: 
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
            
        all_values = ProjectFiles.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class GeoZonesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoZones.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoZones.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoZones.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        gz_country_code        =data.get('gz_country_code') 
        gz_zone_name           =data.get('gz_zone_name')
        c_timestamp  = data.get('c_timestamp')   
        m_timestamp  = data.get('m_timestamp')            
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoZones.objects.create(gz_country_code=gz_country_code,
                                    gz_zone_name=gz_zone_name,
                                    c_timestamp = c_timestamp,
                                    m_timestamp=m_timestamp
                                    )
            posts = GeoZones.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
        
    def put(self,request,pk):
        data = request.data
        gz_country_code        =data.get('gz_country_code') 
        gz_zone_name           =data.get('gz_zone_name')
        c_timestamp  = data.get('c_timestamp')   
        m_timestamp  = data.get('m_timestamp')            

        try:
            GeoZones.objects.filter(id=pk).update(gz_country_code=gz_country_code,
                                    gz_zone_name=gz_zone_name,
                                    c_timestamp  = c_timestamp,   
                                    m_timestamp  = m_timestamp     

                                    )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
        
    def delete(self,request,pk):
        test = (0,{})
        all_values = GeoZones.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class GeoTimezonesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoTimezones.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoTimezones.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoTimezones.objects.all().values().order_by('-id')
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

            # all_data = GeoTimezones.objects.all().values().order_by('-id')
            # return Response({'result':{'status':'GET','data':all_data}})

    def post(self,request):
        data = request.data
        gz_ref              =data.get('gz_ref_id') 
        gtm_abbreviation    =data.get('gtm_abbreviation')  
        gtm_time_start      =data.get('gtm_time_start') 
        gtm_gmt_offset      =data.get('gtm_gmt_offset')  
        gtm_dst             =data.get('gtm_dst')
        c_timestamp = data.get('c_timestamp')    
        m_timestamp = data.get('m_timestamp') 
       
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoTimezones.objects.create(gz_ref_id=gz_ref,
                                        gtm_abbreviation=gtm_abbreviation,
                                        gtm_time_start=gtm_time_start,
                                        gtm_gmt_offset=gtm_gmt_offset,
                                        gtm_dst=gtm_dst,
                                        c_timestamp = c_timestamp,
                                        m_timestamp = m_timestamp
                                        )
            posts = GeoTimezones.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        data = request.data
        gz_ref              =data.get('gz_ref_id') 
        gtm_abbreviation    =data.get('gtm_abbreviation')  
        # gtm_time_start      =data.get('gtm_time_start') 
        gtm_gmt_offset      =data.get('gtm_gmt_offset')  
        gtm_dst             =data.get('gtm_dst')
        c_timestamp = data.get('c_timestamp')
        m_timestamp = data.get('m_timestamp')              
        try:
            GeoTimezones.objects.filter(id=pk).update(gz_ref_id=gz_ref,
                                        gtm_abbreviation=gtm_abbreviation,
                                        # gtm_time_start=gtm_time_start,
                                        gtm_gmt_offset=gtm_gmt_offset,
                                        gtm_dst=gtm_dst,
                                        c_timestamp = c_timestamp,
                                        m_timestamp = m_timestamp
                                        )

            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def delete(self,request,pk):
        test = (0,{})
        all_values = GeoTimezones.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class GeoCurrenciesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoCurrencies.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoCurrencies.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoCurrencies.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        geo_cur_code        = data.get('geo_cur_code')
        geo_cur_name        = data.get('geo_cur_name')
        geo_cur_major_name  = data.get('geo_cur_major_name')
        geo_cur_major_symbol= data.get('geo_cur_major_symbol')
        geo_cur_minor_name  = data.get('geo_cur_minor_name')
        geo_cur_minor_symbol= data.get('geo_cur_minor_symbol')
        geo_cur_minor_value = data.get('geo_cur_minor_value')
        geo_cur_c_date = data.get('geo_cur_c_date')
        geo_cur_m_date = data.get('geo_cur_m_date')

        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoCurrencies.objects.create(geo_cur_code=geo_cur_code,
                                        geo_cur_name=geo_cur_name,
                                        geo_cur_major_name=geo_cur_major_name,
                                        geo_cur_major_symbol=geo_cur_major_symbol,
                                        geo_cur_minor_name=geo_cur_minor_name,
                                        geo_cur_minor_symbol=geo_cur_minor_symbol,
                                        geo_cur_minor_value=geo_cur_minor_value,
                                        geo_cur_c_date = geo_cur_c_date,
                                        geo_cur_m_date = geo_cur_m_date

                                )
            posts = GeoCurrencies.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        geo_cur_code        = data.get('geo_cur_code')
        geo_cur_name        = data.get('geo_cur_name')
        geo_cur_major_name  = data.get('geo_cur_major_name')
        geo_cur_major_symbol= data.get('geo_cur_major_symbol')
        geo_cur_minor_name  = data.get('geo_cur_minor_name')
        geo_cur_minor_symbol= data.get('geo_cur_minor_symbol')
        geo_cur_minor_value = data.get('geo_cur_minor_value')
        geo_cur_c_date  = data.get('geo_cur_c_date')
        geo_cur_m_date  = data.get('geo_cur_c_date')
        try:
            GeoCurrencies.objects.filter(id=pk).update(geo_cur_code=geo_cur_code,
                                        geo_cur_name=geo_cur_name,
                                        geo_cur_major_name=geo_cur_major_name,
                                        geo_cur_major_symbol=geo_cur_major_symbol,
                                        geo_cur_minor_name=geo_cur_minor_name,
                                        geo_cur_minor_symbol=geo_cur_minor_symbol,
                                        geo_cur_minor_value=geo_cur_minor_value,
                                        geo_cur_c_date = geo_cur_c_date,
                                        geo_cur_m_date = geo_cur_m_date
                                    )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
                

    def delete(self,request,pk):
        test = (0,{})
        all_values = GeoCurrencies.objects.filter(id=pk).delete()
        if test == all_values:

            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class GeoCountriesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoCountries.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoCountries.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoCountries.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        gcounty_name    = data.get('gcounty_name')
        gcounty_cca2    = data.get('gcounty_cca2')
        gcounty_cca3    = data.get('gcounty_cca3')
        gcounty_ccn3    = data.get('gcounty_ccn3')
        gcounty_status  = data.get('gcounty_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoCountries.objects.create(gcounty_name=gcounty_name,
                                        gcounty_cca2=gcounty_cca2,
                                        gcounty_cca3=gcounty_cca3,
                                        gcounty_ccn3=gcounty_ccn3,
                                        gcounty_status=gcounty_status,
                                        

                                )
            posts = GeoCountries.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def put(self,request,pk):
        data = request.data
        gcounty_name    = data.get('gcounty_name')
        gcounty_cca2    = data.get('gcounty_cca2')
        gcounty_cca3    = data.get('gcounty_cca3')
        gcounty_ccn3    = data.get('gcounty_ccn3')
        gcounty_status  = data.get('gcounty_status')
        try:
            GeoCountries.objects.filter(id=pk).update(gcounty_name=gcounty_name,
                                                        gcounty_cca2=gcounty_cca2,
                                                        gcounty_cca3=gcounty_cca3,
                                                        gcounty_ccn3=gcounty_ccn3,
                                                        gcounty_status=gcounty_status
                                                    )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})   
        all_values = GeoCountries.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class GeoStatesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoStates.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoStates.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoStates.objects.all().values().order_by('-id')
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


            
    def post(self,request):
        data = request.data
        gstate_name     = data.get('gstate_name')
        gcountry_ref    = data.get('gcountry_ref_id')
        gstate_hasc     = data.get('gstate_hasc')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoStates.objects.create(gstate_name=gstate_name,
                                    gcountry_ref_id=gcountry_ref,
                                    gstate_hasc=gstate_hasc
                                )
            posts = GeoStates.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            


    def put(self,request,pk):
        data = request.data
        gstate_name     = data.get('gstate_name')
        gcountry_ref    = data.get('gcountry_ref_id')
        gstate_hasc     = data.get('gstate_hasc')
        try:
            GeoStates.objects.filter(id=pk).update(gstate_name=gstate_name,
                                                    gcountry_ref_id=gcountry_ref,
                                                    gstate_hasc=gstate_hasc
                                        )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
                


    def delete(self,request,pk):
        test = (0,{})
        all_values = GeoStates.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class GeoCitiesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoCities.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoCities.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoCities.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data
        ref_gcounty     =data.get('ref_gcounty_id')
        gstate_ref      =data.get('gstate_ref_id')
        zone_ref        =data.get('zone_ref_id')
        gcity_name      =data.get('gcity_name')
        gcity_latitude  =data.get('gcity_latitude')
        gcity_longitude =data.get('gcity_longitude')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoCities.objects.create(
                                    ref_gcounty_id=ref_gcounty,
                                    gstate_ref_id=gstate_ref,
                                    zone_ref_id=zone_ref,
                                    gcity_name=gcity_name,
                                    gcity_latitude=gcity_latitude,
                                    gcity_longitude=gcity_longitude
                                )
            posts = GeoCities.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        ref_gcounty     =data.get('ref_gcounty_id')
        gstate_ref      =data.get('gstate_ref_id')
        zone_ref        =data.get('zone_ref_id')
        gcity_name      =data.get('gcity_name')
        gcity_latitude  =data.get('gcity_latitude')
        gcity_longitude =data.get('gcity_longitude')
        try:
            GeoCities.objects.filter(id=pk).update(ref_gcounty_id=ref_gcounty,
                                                    gstate_ref_id=gstate_ref,
                                                    zone_ref_id=zone_ref,
                                                    gcity_name=gcity_name,
                                                    gcity_latitude=gcity_latitude,
                                                    gcity_longitude=gcity_longitude
                                                )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = GeoCities.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



# I have not used any status code here do check this once
@method_decorator([AutorizationRequired], name='dispatch')
class GeoCountriesCurrenciesApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoCountriesCurrencies.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoCountriesCurrencies.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoCountriesCurrencies.objects.all().values().order_by('-id')
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
            
           

    def post(self,request):
        data = request.data
        gcounty_ref      = data.get('gcounty_ref_id')
        geo_cur_ref      = data.get('geo_cur_ref_id')
        c_timestamp = data.get('c_timestamp')
        m_tiemstamp = data.get('m_timestamp')
        
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        # if GeoCountriesCurrencies.objects.filter(gcounty_ref=gcity_name).exists():
        #     return Response({'error':'gcity_name already exists'})
        # else:
        try:
            GeoCountriesCurrencies.objects.create(gcounty_ref_id=gcounty_ref,
                                                geo_cur_ref_id=geo_cur_ref,
                                                c_timestamp = c_timestamp,
                                                m_tiemstamp = m_tiemstamp
                                                )
            posts = GeoCountriesCurrencies.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        gcounty_ref      = data.get('gcounty_ref_id')
        geo_cur_ref      = data.get('geo_cur_ref_id')
        c_tiemstamp  = data.get('c_tiemstamp')
        m_tiemstamp  = data.get('m_tiemstamp')
        # if GeoCountriesCurrencies.objects.filter(gcity_name=gcity_name).exists():
        #     return Response({'error':'gcity_name already exists'})
        # else:
        try:
            GeoCountriesCurrencies.objects.filter(id=pk).update(gcounty_ref_id=gcounty_ref,
                                                geo_cur_ref_id=geo_cur_ref,
                                                c_tiemstamp  = c_tiemstamp,
                                                m_tiemstamp = m_tiemstamp
                                                )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
    def delete(self,request,pk):
        all_values = GeoCountriesCurrencies.objects.filter(id=pk).delete()
        return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class GeoContinentsApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoContinents.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoContinents.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoContinents.objects.all().values().order_by('-id')
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


            # all_data = GeoContinents.objects.all().values().order_by('-id')
            # return Response({'result':{'status':'GET','data':all_data}})

    def post(self,request):
        data = request.data
        gc_name      = data.get('gc_name')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoContinents.objects.create(gc_name =gc_name
                                        )
            posts = GeoContinents.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        gc_name      = data.get('gc_name')
        try:
            GeoContinents.objects.filter(id=pk).update(gc_name =gc_name
                                                            )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = GeoContinents.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class GeoSubContinentsApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = GeoSubContinents.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = GeoSubContinents.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = GeoSubContinents.objects.all().values().order_by('-id')
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

            

            # all_data = GeoSubContinents.objects.all().values().order_by('-id')
            # return Response({'result':{'status':'GET','data':all_data}})
    def post(self,request):
        data = request.data
        gc_ref      = data.get('gc_ref_id')
        gsc_name    = data.get('gsc_name')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            GeoSubContinents.objects.create(
                                            gc_ref_id=gc_ref,
                                            gsc_name=gsc_name
                                        )
            posts = GeoSubContinents.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def put(self,request,pk):
        data = request.data
        gc_ref      = data.get('gc_ref_id')
        gsc_name    = data.get('gsc_name')
        try:
            GeoSubContinents.objects.filter(id=pk).update(gc_ref_id=gc_ref,
                                                            gsc_name=gsc_name
                                                        )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})  
        all_values = GeoSubContinents.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class ProjectCategoriesView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ProjectCategories.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = ProjectCategories.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = ProjectCategories.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data
        org_ref                 = data.get('org_ref_id')
        pc_added_by_ref_user    = data.get('pc_added_by_ref_user_id')
        pc_name                 = data.get('pc_name')
        pc_status               = data.get('pc_status')
        # pc_c_date            = data.get('pc_c_date')
        # pc_m_date              = data.get('pc_m_date')
        # file_attachment_name= data.get('file_attachment_name')
        task_name= data.get('task_name')
        billable_type= data.get('billable_type')
        file_attachment = data['file_attachment']
        base64_data = file_attachment
        split_base_url_data=file_attachment.split(';base64,')[1]
        imgdata1 = base64.b64decode(split_base_url_data)
        data_split = file_attachment.split(';base64,')[0]
        extension_data = re.split(':|;', data_split)[1] 
        guess_extension_data = guess_extension(extension_data)
        filename1 = "/eztime/django/site/media/file_attachment/"+pc_name+guess_extension_data
        # filename1 = "/Users/apple/EzTime/eztimeproject/media/photo"+first_name+guess_extension_data
        fname1 = '/file_attachment/'+pc_name+guess_extension_data
        ss=  open(filename1, 'wb')
        print(ss)
        ss.write(imgdata1)
        ss.close()
        # file_attachment_path='http://127.0.0.1:8000/media/file_attachment/'+ file_attachment.name
        # file_attachment_path='https://projectaceuat.thestorywallcafe.com/media/'+file_attachment
        # print(file_attachment_path,'pathhh')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            check_data = ProjectCategories.objects.create(org_ref_id=org_ref,
                                            pc_added_by_ref_user_id=pc_added_by_ref_user,
                                            pc_name=pc_name,
                                            pc_status=pc_status,
                                            # base64=base64_data,
                                            # pc_c_date=pc_c_date,
                                            # pc_m_date=pc_m_date,
                                            # file_attachment=file_attachment,
                                            # file_attachment_name=file_attachment_name,
                                            task_name=task_name,
                                            billable_type=billable_type,)
                                            # file_attachment_path=file_attachment_path)
            if file_attachment:
                check_data.file_attachment_path = 'https://projectaceuat.thestorywallcafe.com/media/'+ (str(fname1))
                check_data.save()
            posts = ProjectCategories.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        org_ref                 = data.get('org_ref_id')
        pc_added_by_ref_user    = data.get('pc_added_by_ref_user_id')
        pc_name                 = data.get('pc_name')
        pc_status               = data.get('pc_status')
        # pc_c_date               = data.get('pc_c_date')
        # pc_m_date               = data.get('pc_m_date')
        # file_attachment_name= data.get('file_attachment_name')
        task_name= data.get('task_name')
        billable_type= data.get('billable_type')
        file_attachment = data['file_attachment']
        # file_attachment_path='http://127.0.0.1:8000/media/file_attachment/'+ file_attachment.name
        # file_attachment_path='https://projectaceuat.thestorywallcafe.com/media/'+file_attachment
        # print(file_attachment_path,'pathhh')
        if file_attachment == '':
            print('in if nulll looopp') 
            try:
                ProjectCategories.objects.filter(id=pk).update(
                    org_ref_id=org_ref,
                                                pc_added_by_ref_user_id=pc_added_by_ref_user,
                                                pc_name=pc_name,
                                                pc_status=pc_status,

                                                # pc_c_date=pc_c_date,
                                                # pc_m_date=pc_m_date,
                                                # file_attachment=file_attachment,
                                                # file_attachment_name=file_attachment_name,
                                                task_name=task_name,
                                                billable_type=billable_type,)
                return Response({'result':{'status':'Updated'}})
            except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
        try:

            base64_data = file_attachment
            split_base_url_data=file_attachment.split(';base64,')[1]
            imgdata1 = base64.b64decode(split_base_url_data)

            data_split = file_attachment.split(';base64,')[0]
            extension_data = re.split(':|;', data_split)[1] 
            guess_extension_data = guess_extension(extension_data)

            filename1 = "/eztime/django/site/media/file_attachment/"+pc_name+guess_extension_data
            # filename1 = "/Users/apple/EzTime/eztimeproject/media/photo"+first_name+guess_extension_data
            fname1 = '/file_attachment/'+pc_name+guess_extension_data
            ss=  open(filename1, 'wb')
            print(ss)
            ss.write(imgdata1)
            ss.close()   
            ProjectCategories.objects.filter(id=pk).update(
                   
                                                file_attachment='',
                                                )
            ProjectCategories.objects.filter(id=pk).update(
                    org_ref_id=org_ref,
                                                pc_added_by_ref_user_id=pc_added_by_ref_user,
                                                pc_name=pc_name,
                                                pc_status=pc_status,
                                                # base64=base64_data,
                                                # pc_c_date=pc_c_date,
                                                # pc_m_date=pc_m_date,
                                                file_attachment=file_attachment,
                                                # file_attachment_name=file_attachment_name,
                                                task_name=task_name,
                                                billable_type=billable_type,)
            check_data = ProjectCategories.objects.get(id=pk)
            if file_attachment:
                    print(check_data.file_attachment,"this is file")
                    check_data.file_attachment_path = 'https://projectaceuat.thestorywallcafe.com/media/file_attachment/'+ (str(check_data.file_attachment))
                    
                    check_data.save()
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        test = (0,{})
        all_values = ProjectCategories.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


#------------------------------------------------------------------------
@method_decorator([AutorizationRequired], name='dispatch')
class ProductDetailsView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ProductDetails.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = ProductDetails.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = ProductDetails.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        pd_app_name      = data.get('pd_app_name')
        pd_app_tag_line= data.get('pd_app_tag_line')
        pd_company_name= data.get('pd_company_name')
        pd_company_address= data.get('pd_company_address')
        pd_company_email_id= data.get('pd_company_email_id')
        pd_company_phone_no= data.get('pd_company_phone_no')
        pd_web_version= data.get('pd_web_version')
        pd_poweredbyweblink= data.get('pd_poweredbyweblink')
        pd_facebook_link= data.get('pd_facebook_link')
        pd_twitter_link= data.get('pd_twitter_link')
        pd_linkedin_link= data.get('pd_linkedin_link')
        pd_product_logo= data.get('pd_product_logo')
        pd_product_logo_base_url= data.get('pd_product_logo_base_url')
        pd_product_logo_path= data.get('pd_product_logo_path')
        pd_status= data.get('pd_status')

        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            ProductDetails.objects.create(pd_app_name=pd_app_name,
                                        pd_app_tag_line=pd_app_tag_line,
                                        pd_company_name=pd_company_name,
                                        pd_company_address=pd_company_address,
                                        pd_company_email_id=pd_company_email_id,
                                        pd_company_phone_no=pd_company_phone_no,
                                        pd_web_version=pd_web_version,
                                        pd_poweredbyweblink=pd_poweredbyweblink,
                                        pd_facebook_link=pd_facebook_link,
                                        pd_twitter_link=pd_twitter_link,
                                        pd_linkedin_link=pd_linkedin_link,
                                        pd_product_logo=pd_product_logo,
                                        pd_product_logo_base_url=pd_product_logo_base_url,
                                        pd_product_logo_path=pd_product_logo_path,
                                        pd_status=pd_status)
            posts = ProductDetails.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        pd_app_name      = data.get('pd_app_name')
        pd_app_tag_line= data.get('pd_app_tag_line')
        pd_company_name= data.get('pd_company_name')
        pd_company_address= data.get('pd_company_address')
        pd_company_email_id= data.get('pd_company_email_id')
        pd_company_phone_no= data.get('pd_company_phone_no')
        pd_web_version= data.get('pd_web_version')
        pd_poweredbyweblink= data.get('pd_poweredbyweblink')
        pd_facebook_link= data.get('pd_facebook_link')
        pd_twitter_link= data.get('pd_twitter_link')
        pd_linkedin_link= data.get('pd_linkedin_link')
        pd_product_logo= data.get('pd_product_logo')
        pd_product_logo_base_url= data.get('pd_product_logo_base_url')
        pd_product_logo_path= data.get('pd_product_logo_path')
        pd_status= data.get('pd_status')
        try:
            ProductDetails.objects.filter(id=pk).update(pd_app_name=pd_app_name,
                                        pd_app_tag_line=pd_app_tag_line,
                                        pd_company_name=pd_company_name,
                                        pd_company_address=pd_company_address,
                                        pd_company_email_id=pd_company_email_id,
                                        pd_company_phone_no=pd_company_phone_no,
                                        pd_web_version=pd_web_version,
                                        pd_poweredbyweblink=pd_poweredbyweblink,
                                        pd_facebook_link=pd_facebook_link,
                                        pd_twitter_link=pd_twitter_link,
                                        pd_linkedin_link=pd_linkedin_link,
                                        pd_product_logo=pd_product_logo,
                                        pd_product_logo_base_url=pd_product_logo_base_url,
                                        pd_product_logo_path=pd_product_logo_path,
                                        pd_status=pd_status)

            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = ProductDetails.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class OrganizationLeaveTypeApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = OrganizationLeaveType.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = OrganizationLeaveType.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = OrganizationLeaveType.objects.all().values().order_by('-id')
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


        
    def post(self,request):
        data = request.data
        org_reff = data.get('org_reff_id')
        olt_added_by_ref_user= data.get('olt_added_by_ref_user_id')
        olt_ref_occ_id_list= data.get('olt_ref_occ_id_list')
        olt_name= data.get('olt_name')
        olt_description= data.get('olt_description')
        olt_status= data.get('olt_status')
        olt_no_of_leaves= data.get('olt_no_of_leaves')
        olt_no_of_leaves_yearly= data.get('olt_no_of_leaves_yearly')
        olt_no_of_leaves_monthly= data.get('olt_no_of_leaves_monthly')
        olt_accrude_monthly_status= data.get('olt_accrude_monthly_status')
        olt_carry_forward= data.get('olt_carry_forward')
        olt_applicable_for= data.get('olt_applicable_for')
        olt_people_applicable_for= data.get('olt_people_applicable_for')
        olt_gracefull_status= data.get('olt_gracefull_status')
        olt_gracefull_days= data.get('olt_gracefull_days')
        olt_enchashment_status= data.get('olt_enchashment_status')
        olt_max_enchashment_leaves= data.get('olt_max_enchashment_leaves')
        olt_editable= data.get('olt_editable')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            OrganizationLeaveType.objects.create(org_reff_id=org_reff,
                                            olt_added_by_ref_user_id=olt_added_by_ref_user,
                                            olt_ref_occ_id_list=olt_ref_occ_id_list,
                                            olt_name=olt_name,
                                            olt_description=olt_description,
                                            olt_status=olt_status,
                                            olt_no_of_leaves=olt_no_of_leaves,
                                            olt_no_of_leaves_yearly=olt_no_of_leaves_yearly,
                                            olt_no_of_leaves_monthly=olt_no_of_leaves_monthly,
                                            olt_accrude_monthly_status=olt_accrude_monthly_status,
                                            olt_carry_forward=olt_carry_forward,
                                            olt_applicable_for=olt_applicable_for,
                                            olt_people_applicable_for=olt_people_applicable_for,
                                            olt_gracefull_status=olt_gracefull_status,
                                            olt_gracefull_days=olt_gracefull_days,
                                            olt_enchashment_status=olt_enchashment_status,
                                            olt_max_enchashment_leaves=olt_max_enchashment_leaves,
                                            olt_editable=olt_editable)
            posts = OrganizationLeaveType.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        org_reff = data.get('org_reff_id')
        olt_added_by_ref_user= data.get('olt_added_by_ref_user_id')
        olt_ref_occ_id_list= data.get('olt_ref_occ_id_list')
        olt_name= data.get('olt_name')
        olt_description= data.get('olt_description')
        olt_status= data.get('olt_status')
        olt_no_of_leaves= data.get('olt_no_of_leaves')
        olt_no_of_leaves_yearly= data.get('olt_no_of_leaves_yearly')
        olt_no_of_leaves_monthly= data.get('olt_no_of_leaves_monthly')
        olt_accrude_monthly_status= data.get('olt_accrude_monthly_status')
        olt_carry_forward= data.get('olt_carry_forward')
        olt_applicable_for= data.get('olt_applicable_for')
        olt_people_applicable_for= data.get('olt_people_applicable_for')
        olt_gracefull_status= data.get('olt_gracefull_status')
        olt_gracefull_days= data.get('olt_gracefull_days')
        olt_enchashment_status= data.get('olt_enchashment_status')
        olt_max_enchashment_leaves= data.get('olt_max_enchashment_leaves')
        olt_editable= data.get('olt_editable')
        try:
            OrganizationLeaveType.objects.filter(id=pk).update(org_reff_id=org_reff,
                                            olt_added_by_ref_user_id=olt_added_by_ref_user,
                                            olt_ref_occ_id_list=olt_ref_occ_id_list,
                                            olt_name=olt_name,
                                            olt_description=olt_description,
                                            olt_status=olt_status,
                                            olt_no_of_leaves=olt_no_of_leaves,
                                            olt_no_of_leaves_yearly=olt_no_of_leaves_yearly,
                                            olt_no_of_leaves_monthly=olt_no_of_leaves_monthly,
                                            olt_accrude_monthly_status=olt_accrude_monthly_status,
                                            olt_carry_forward=olt_carry_forward,
                                            olt_applicable_for=olt_applicable_for,
                                            olt_people_applicable_for=olt_people_applicable_for,
                                            olt_gracefull_status=olt_gracefull_status,
                                            olt_gracefull_days=olt_gracefull_days,
                                            olt_enchashment_status=olt_enchashment_status,
                                            olt_max_enchashment_leaves=olt_max_enchashment_leaves,
                                            olt_editable=olt_editable)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            


    def delete(self,request,pk):
        test = (0,{})
        all_values = OrganizationLeaveType.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class OrganizationCostCentersApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = OrganizationCostCenters.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = OrganizationCostCenters.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = OrganizationCostCenters.objects.all().values().order_by('-id')
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


            

    def post(self,request):
        data = request.data
        org_ref = data.get('org_ref_id')
        occ_added_by_ref_user= data.get('occ_added_by_ref_user_id')
        occ_cost_center_name= data.get('occ_cost_center_name')
        occ_leave_mgmt_status= data.get('occ_leave_mgmt_status')
        occ_currency_type= data.get('occ_currency_type')
        occ_status= data.get('occ_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            OrganizationCostCenters.objects.create(org_ref_id=org_ref,
                                                        occ_added_by_ref_user_id=occ_added_by_ref_user,
                                                        occ_cost_center_name=occ_cost_center_name,
                                                        occ_leave_mgmt_status=occ_leave_mgmt_status,
                                                        occ_currency_type=occ_currency_type,
                                                        occ_status=occ_status)
            posts = OrganizationCostCenters.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        org_ref = data.get('org_ref_id')
        occ_added_by_ref_user= data.get('occ_added_by_ref_user_id')
        occ_cost_center_name= data.get('occ_cost_center_name')
        occ_leave_mgmt_status= data.get('occ_leave_mgmt_status')
        occ_currency_type= data.get('occ_currency_type')
        occ_status= data.get('occ_status')
        try:
            OrganizationCostCenters.objects.filter(id=pk).update(org_ref_id=org_ref,
                                                        occ_added_by_ref_user_id=occ_added_by_ref_user,
                                                        occ_cost_center_name=occ_cost_center_name,
                                                        occ_leave_mgmt_status=occ_leave_mgmt_status,
                                                        occ_currency_type=occ_currency_type,
                                                        occ_status=occ_status)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
                
    def delete(self,request,pk):
        test = (0,{})
        all_values = OrganizationCostCenters.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class OrganizationCostCentersLeaveTypeApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = OrganizationCostCentersLeaveType.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = OrganizationCostCentersLeaveType.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = OrganizationCostCentersLeaveType.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        olt_ref=data.get('olt_ref_id')
        org_ref=data.get('org_ref_id')
        occ_ref=data.get('occ_ref_id')
        occl_added_by_ref_user=data.get('occl_added_by_ref_user_id')
        occl_name=data.get('occl_name')
        occl_description=data.get('occl_description')
        occl_status=data.get('occl_status')
        occl_alloted_leaves=data.get('occl_alloted_leaves')
        occl_alloted_leaves_yearly=data.get('occl_alloted_leaves_yearly')
        occl_alloted_leaves_monthly=data.get('occl_alloted_leaves_monthly')
        occl_accrude_monthly_status=data.get('occl_accrude_monthly_status')
        occl_carry_forward=data.get('occl_carry_forward')
        occl_gracefull_status=data.get('occl_gracefull_status')
        occl_gracefull_days=data.get('occl_gracefull_days')
        occl_enchashment_status=data.get('occl_enchashment_status')
        occl_max_enchashment_leaves=data.get('occl_max_enchashment_leaves')
        occl_editable=data.get('occl_editable')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            OrganizationCostCentersLeaveType.objects.create(olt_ref_id=olt_ref,
                                                            org_ref_id=org_ref,
                                                            occ_ref_id=occ_ref,
                                                            occl_added_by_ref_user_id=occl_added_by_ref_user,
                                                            occl_name=occl_name,
                                                            occl_description=occl_description,
                                                            occl_status=occl_status,
                                                            occl_alloted_leaves=occl_alloted_leaves,
                                                            occl_alloted_leaves_yearly=occl_alloted_leaves_yearly,
                                                            occl_alloted_leaves_monthly=occl_alloted_leaves_monthly,
                                                            occl_accrude_monthly_status=occl_accrude_monthly_status,
                                                            occl_carry_forward=occl_carry_forward,
                                                            occl_gracefull_status=occl_gracefull_status,
                                                            occl_gracefull_days=occl_gracefull_days,
                                                            occl_enchashment_status=occl_enchashment_status,
                                                            occl_max_enchashment_leaves=occl_max_enchashment_leaves,
                                                            occl_editable=occl_editable)


            posts = OrganizationCostCentersLeaveType.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        olt_ref=data.get('olt_ref_id')
        org_ref=data.get('org_ref_id')
        occ_ref=data.get('occ_ref_id')
        occl_added_by_ref_user=data.get('occl_added_by_ref_user_id')
        occl_name=data.get('occl_name')
        occl_description=data.get('occl_description')
        occl_status=data.get('occl_status')
        occl_alloted_leaves=data.get('occl_alloted_leaves')
        occl_alloted_leaves_yearly=data.get('occl_alloted_leaves_yearly')
        occl_alloted_leaves_monthly=data.get('occl_alloted_leaves_monthly')
        occl_accrude_monthly_status=data.get('occl_accrude_monthly_status')
        occl_carry_forward=data.get('occl_carry_forward')
        occl_gracefull_status=data.get('occl_gracefull_status')
        occl_gracefull_days=data.get('occl_gracefull_days')
        occl_enchashment_status=data.get('occl_enchashment_status')
        occl_max_enchashment_leaves=data.get('occl_max_enchashment_leaves')
        occl_editable=data.get('occl_editable')
        try:
            OrganizationCostCentersLeaveType.objects.filter(id=pk).update(olt_ref_id=olt_ref,
                                                            org_ref_id=org_ref,
                                                            occ_ref_id=occ_ref,
                                                            occl_added_by_ref_user_id=occl_added_by_ref_user,
                                                            occl_name=occl_name,
                                                            occl_description=occl_description,
                                                            occl_status=occl_status,
                                                            occl_alloted_leaves=occl_alloted_leaves,
                                                            occl_alloted_leaves_yearly=occl_alloted_leaves_yearly,
                                                            occl_alloted_leaves_monthly=occl_alloted_leaves_monthly,
                                                            occl_accrude_monthly_status=occl_accrude_monthly_status,
                                                            occl_carry_forward=occl_carry_forward,
                                                            occl_gracefull_status=occl_gracefull_status,
                                                            occl_gracefull_days=occl_gracefull_days,
                                                            occl_enchashment_status=occl_enchashment_status,
                                                            occl_max_enchashment_leaves=occl_max_enchashment_leaves,
                                                            occl_editable=occl_editable)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = OrganizationCostCentersLeaveType.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class UsersLeaveMasterApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = UsersLeaveMaster.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = UsersLeaveMaster.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = UsersLeaveMaster.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        org_ref=data.get('org_ref_id')
        ulm_ref_user=data.get('ulm_ref_user_id')
        occ_ref=data.get('occ_ref_id')
        occl_ref=data.get('occl_ref_id')
        occyl_ref=data.get('occyl_ref_id')
        ulm_added_by_ref_id=data.get('ulm_added_by_ref_id')
        ulm_allotted_leaves=data.get('ulm_allotted_leaves')
        ulm_leaves_used=data.get('ulm_leaves_used')
        ulm_status=data.get('ulm_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            UsersLeaveMaster.objects.create(org_ref_id=org_ref,
                                    ulm_ref_user_id=ulm_ref_user,
                                    occ_ref_id=occ_ref,
                                    occl_ref_id=occl_ref,
                                    occyl_ref_id=occyl_ref,
                                    ulm_added_by_ref_id=ulm_added_by_ref_id,
                                    ulm_allotted_leaves=ulm_allotted_leaves,
                                    ulm_leaves_used=ulm_leaves_used,
                                    ulm_status=ulm_status)
            return Response({'result':{'status':'UsersLeaveMaster Created'}})
        # posts = UsersLeaveMaster.objects.all().values().order_by('-id')
        # paginator = Paginator(posts,10)
        # try:
        #     page_obj = paginator.get_page(selected_page_no)
        #     except PageNotAnInteger:
        #         page_obj = paginator.page(1)
        #     except EmptyPage:
        #         page_obj = paginator.page(paginator.num_pages)
        #     return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        org_ref=data.get('org_ref_id')
        ulm_ref_user=data.get('ulm_ref_user_id')
        occ_ref=data.get('occ_ref_id')
        occl_ref=data.get('occl_ref_id')
        occyl_ref=data.get('occyl_ref_id')
        ulm_added_by_ref_id=data.get('ulm_added_by_ref_id')
        ulm_allotted_leaves=data.get('ulm_allotted_leaves')
        ulm_leaves_used=data.get('ulm_leaves_used')
        ulm_status=data.get('ulm_status')
        try:
            UsersLeaveMaster.objects.filter(id=pk).update(org_ref_id=org_ref,
                                ulm_ref_user_id=ulm_ref_user,
                                occ_ref_id=occ_ref,
                                occl_ref_id=occl_ref,
                                occyl_ref_id=occyl_ref,
                                ulm_added_by_ref_id=ulm_added_by_ref_id,
                                ulm_allotted_leaves=ulm_allotted_leaves,
                                ulm_leaves_used=ulm_leaves_used,
                                ulm_status=ulm_status)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = UsersLeaveMaster.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class OrganizationCostCentersYearListApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = OrganizationCostCentersYearList.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = OrganizationCostCentersYearList.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = OrganizationCostCentersYearList.objects.all().values().order_by('-id')
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

            
            

    def post(self,request):
        data = request.data
        org_ref =data.get('org_ref_id')
        occyl_added_by_ref_user =data.get('occyl_added_by_ref_user_id')
        occ_ref =data.get('occ_ref_id')
        occyl_status =data.get('occyl_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            OrganizationCostCentersYearList.objects.create(org_ref_id=org_ref,
                                                                occyl_added_by_ref_user_id=occyl_added_by_ref_user,
                                                                occ_ref_id=occ_ref,
                                                                occyl_status=occyl_status)
            posts = OrganizationCostCentersYearList.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        org_ref =data.get('org_ref_id')
        occyl_added_by_ref_user =data.get('occyl_added_by_ref_user_id')
        occ_ref =data.get('occ_ref_id')
        occyl_status =data.get('occyl_status')
        try:
            OrganizationCostCentersYearList.objects.filter(id=pk).update(org_ref_id=org_ref,
                                                                occyl_added_by_ref_user_id=occyl_added_by_ref_user,
                                                                occ_ref_id=occ_ref,
                                                                occyl_status=occyl_status)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
                

    def delete(self,request,pk):
        test = (0,{})
        all_values = OrganizationCostCentersYearList.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class UsersLeaveApplicationsApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = UsersLeaveApplications.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = UsersLeaveApplications.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = UsersLeaveApplications.objects.all().values().order_by('-id')
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


    def post(self,request):
        data = request.data
        org_ref=data.get('org_ref_id')
        ula_ref_user=data.get('ula_ref_user_id')
        occl_ref=data.get('occl_ref_id')
        ulm_ref=data.get('ulm_ref_id')
        ula_approved_by_ref_u_id=data.get('ula_approved_by_ref_u_id')
        ula_cc_to_ref_u_id=data.get('ula_cc_to_ref_u_id')
        ula_reason_for_leave=data.get('ula_reason_for_leave')
        ula_contact_details=data.get('ula_contact_details')
        ula_file=data.get('ula_file')
        ula_file_path=data.get('ula_file_path')
        ula_file_base_url=data.get('ula_file_base_url')
        ula_cc_mail_sent=data.get('ula_cc_mail_sent')
        ula_from_session=data.get('ula_from_session')
        ula_to_session=data.get('ula_to_session')
        ula_no_of_days_leaves=data.get('ula_no_of_days_leaves')
        ula_approved_leaves=data.get('ula_approved_leaves')
        ula_rejected_leaves=data.get('ula_rejected_leaves')
        ula_pending_leaves=data.get('ula_pending_leaves')
        ula_balanced_leaves=data.get('ula_balanced_leaves')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            UsersLeaveApplications.objects.create(org_ref_id=org_ref,
                                                    ula_ref_user_id=ula_ref_user,
                                                    occl_ref_id=occl_ref,
                                                    ulm_ref_id=ulm_ref,
                                                    ula_approved_by_ref_u_id=ula_approved_by_ref_u_id,
                                                    ula_cc_to_ref_u_id=ula_cc_to_ref_u_id,
                                                    ula_reason_for_leave=ula_reason_for_leave,
                                                    ula_contact_details=ula_contact_details,
                                                    ula_file=ula_file,
                                                    ula_file_path=ula_file_path,
                                                    ula_file_base_url=ula_file_base_url,
                                                    ula_cc_mail_sent=ula_cc_mail_sent,
                                                    ula_from_session=ula_from_session,
                                                    ula_to_session=ula_to_session,
                                                    ula_no_of_days_leaves=ula_no_of_days_leaves,
                                                    ula_approved_leaves=ula_approved_leaves,
                                                    ula_rejected_leaves=ula_rejected_leaves,
                                                    ula_pending_leaves=ula_pending_leaves,
                                                    ula_balanced_leaves=ula_balanced_leaves)

            posts = UsersLeaveApplications.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        org_ref=data.get('org_ref_id')
        ula_ref_user=data.get('ula_ref_user_id')
        occl_ref=data.get('occl_ref_id')
        ulm_ref=data.get('ulm_ref_id')
        ula_approved_by_ref_u_id=data.get('ula_approved_by_ref_u_id')
        ula_cc_to_ref_u_id=data.get('ula_cc_to_ref_u_id')
        ula_reason_for_leave=data.get('ula_reason_for_leave')
        ula_contact_details=data.get('ula_contact_details')
        ula_file=data.get('ula_file')
        ula_file_path=data.get('ula_file_path')
        ula_file_base_url=data.get('ula_file_base_url')
        ula_cc_mail_sent=data.get('ula_cc_mail_sent')
        ula_from_session=data.get('ula_from_session')
        ula_to_session=data.get('ula_to_session')
        ula_no_of_days_leaves=data.get('ula_no_of_days_leaves')
        ula_approved_leaves=data.get('ula_approved_leaves')
        ula_rejected_leaves=data.get('ula_rejected_leaves')
        ula_pending_leaves=data.get('ula_pending_leaves')
        ula_balanced_leaves=data.get('ula_balanced_leaves')
        try:
            UsersLeaveApplications.objects.filter(id=pk).update(org_ref_id=org_ref,
                                                    ula_ref_user_id=ula_ref_user,
                                                    occl_ref_id=occl_ref,
                                                    ulm_ref_id=ulm_ref,
                                                    ula_approved_by_ref_u_id=ula_approved_by_ref_u_id,
                                                    ula_cc_to_ref_u_id=ula_cc_to_ref_u_id,
                                                    ula_reason_for_leave=ula_reason_for_leave,
                                                    ula_contact_details=ula_contact_details,
                                                    ula_file=ula_file,
                                                    ula_file_path=ula_file_path,
                                                    ula_file_base_url=ula_file_base_url,
                                                    ula_cc_mail_sent=ula_cc_mail_sent,
                                                    ula_from_session=ula_from_session,
                                                    ula_to_session=ula_to_session,
                                                    ula_no_of_days_leaves=ula_no_of_days_leaves,
                                                    ula_approved_leaves=ula_approved_leaves,
                                                    ula_rejected_leaves=ula_rejected_leaves,
                                                    ula_pending_leaves=ula_pending_leaves,
                                                    ula_balanced_leaves=ula_balanced_leaves)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = UsersLeaveApplications.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class UserLeaveAllotmentListApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = UserLeaveAllotmentList.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = UserLeaveAllotmentList.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = UserLeaveAllotmentList.objects.all().values().order_by('-id')
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


            

            
    
    def post(self,request):
        data = request.data
        org_ref=data.get('org_ref_id')
        occ_ref=data.get('occ_ref_id')
        occyl_ref=data.get('occyl_ref_id')
        occl_ref=data.get('occl_ref_id')
        ulm_ref=data.get('ulm_ref_id')
        ulal_ref_user=data.get('ulal_ref_user_id')
        ula_ref=data.get('ula_ref_id')
        ulal_allotted_leaves=data.get('ulal_allotted_leaves')
        ulal_status=data.get('ulal_status')
        ulal_type=data.get('ulal_type')
        ulal_type_of_allotment=data.get('ulal_type_of_allotment')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)        
        try:
            UserLeaveAllotmentList.objects.create(org_ref_id=org_ref,
                                                    occ_ref_id=occ_ref,
                                                    occyl_ref_id=occyl_ref,
                                                    occl_ref_id=occl_ref,
                                                    ulm_ref_id=ulm_ref,
                                                    ulal_ref_user_id=ulal_ref_user,
                                                    ula_ref_id=ula_ref,
                                                    ulal_allotted_leaves=ulal_allotted_leaves,
                                                    ulal_status=ulal_status,
                                                    ulal_type=ulal_type,
                                                    ulal_type_of_allotment=ulal_type_of_allotment)
            posts = UserLeaveAllotmentList.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            


    def put(self,request,pk):
        data = request.data
        org_ref=data.get('org_ref_id')
        occ_ref=data.get('occ_ref_id')
        occyl_ref=data.get('occyl_ref_id')
        occl_ref=data.get('occl_ref_id')
        ulm_ref=data.get('ulm_ref_id')
        ulal_ref_user=data.get('ulal_ref_user_id')
        ula_ref=data.get('ula_ref_id')
        ulal_allotted_leaves=data.get('ulal_allotted_leaves')
        ulal_status=data.get('ulal_status')
        ulal_type=data.get('ulal_type')
        ulal_type_of_allotment=data.get('ulal_type_of_allotment')
        try:
            UserLeaveAllotmentList.objects.filter(id=pk).update(org_ref_id=org_ref,
                                                    occ_ref_id=occ_ref,
                                                    occyl_ref_id=occyl_ref,
                                                    occl_ref_id=occl_ref,
                                                    ulm_ref_id=ulm_ref,
                                                    ulal_ref_user_id=ulal_ref_user,
                                                    ula_ref_id=ula_ref,
                                                    ulal_allotted_leaves=ulal_allotted_leaves,
                                                    ulal_status=ulal_status,
                                                    ulal_type=ulal_type,
                                                    ulal_type_of_allotment=ulal_type_of_allotment)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
                
    def delete(self,request,pk):
        test = (0,{})
        all_values = UserLeaveAllotmentList.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class UserLeaveListApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = UserLeaveList.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = UserLeaveList.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = UserLeaveList.objects.all().values().order_by('-id')
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
            

    def post(self,request):
        data = request.data
        org_ref=data.get('org_ref_id')
        ull_ref_user=data.get('ull_ref_user_id')
        olt_ref=data.get('olt_ref_id')
        occ_ref=data.get('occ_ref_id')
        ull_added_by_ref_id=data.get('ull_added_by_ref_user_id')
        ull_ref_ohcy_id=data.get('ull_ref_ohcy_id')
        ull_no_of_allotted_leaves=data.get('ull_no_of_allotted_leaves')
        ull_no_of_leaves_used=data.get('ull_no_of_leaves_used')
        ull_status=data.get('ull_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)        
        try:
            UserLeaveList.objects.create(org_ref_id=org_ref,
                                        ull_ref_user_id=ull_ref_user,
                                        olt_ref_id=olt_ref,
                                        occ_ref_id=occ_ref,
                                        ull_added_by_ref_user_id=ull_added_by_ref_id,
                                        ull_ref_ohcy_id=ull_ref_ohcy_id,
                                        ull_no_of_allotted_leaves=ull_no_of_allotted_leaves,
                                        ull_no_of_leaves_used=ull_no_of_leaves_used,
                                        ull_status=ull_status)
            posts = UserLeaveList.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def put(self,request,pk):
        data = request.data
        org_ref=data.get('org_ref_id')
        ull_ref_user=data.get('ull_ref_user_id')
        olt_ref=data.get('olt_ref_id')
        occ_ref=data.get('occ_ref_id')
        ull_added_by_ref_id=data.get('ull_added_by_ref_user_id')
        ull_ref_ohcy_id=data.get('ull_ref_ohcy_id')
        ull_no_of_allotted_leaves=data.get('ull_no_of_allotted_leaves')
        ull_no_of_leaves_used=data.get('ull_no_of_leaves_used')
        ull_status=data.get('ull_status')
        try:
            UserLeaveList.objects.filter(id=pk).update(org_ref_id=org_ref,
                                        ull_ref_user_id=ull_ref_user,
                                        olt_ref_id=olt_ref,
                                        occ_ref_id=occ_ref,
                                        ull_added_by_ref_user_id=ull_added_by_ref_id,
                                        ull_ref_ohcy_id=ull_ref_ohcy_id,
                                        ull_no_of_allotted_leaves=ull_no_of_allotted_leaves,
                                        ull_no_of_leaves_used=ull_no_of_leaves_used,
                                        ull_status=ull_status)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = UserLeaveList.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class ProjectCategoriesChecklistApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = ProjectCategoriesChecklist.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            
            all_data = ProjectCategoriesChecklist.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = ProjectCategoriesChecklist.objects.all().values().order_by('-id')
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
            


    def post(self,request):
        data = request.data
        org_ref=data.get('org_ref_id')
        pcc_added_by_ref_user=data.get('pcc_added_by_ref_user_id')
        pc_ref=data.get('pc_ref_id')
        pcc_name=data.get('pcc_name')
        pcc_billable=data.get('pcc_billable')
        pcc_status=data.get('pcc_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            ProjectCategoriesChecklist.objects.create(org_ref_id=org_ref,
                                                        pcc_added_by_ref_user_id=pcc_added_by_ref_user,
                                                        pc_ref_id=pc_ref,
                                                        pcc_name=pcc_name,
                                                        pcc_billable=pcc_billable,
                                                        pcc_status=pcc_status)
            posts = ProjectCategoriesChecklist.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def put(self,request,pk):
        data = request.data
        org_ref=data.get('org_ref_id')
        pcc_added_by_ref_user=data.get('pcc_added_by_ref_user_id')
        pc_ref=data.get('pc_ref_id')
        pcc_name=data.get('pcc_name')
        pcc_billable=data.get('pcc_billable')
        pcc_status=data.get('pcc_status')
        try:
            ProjectCategoriesChecklist.objects.filter(id=pk).update(org_ref_id=org_ref,
                                                        pcc_added_by_ref_user_id=pcc_added_by_ref_user,
                                                        pc_ref_id=pc_ref,
                                                        pcc_name=pcc_name,
                                                        pcc_billable=pcc_billable,
                                                        pcc_status=pcc_status)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = ProjectCategoriesChecklist.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class TaskProjectCategoriesChecklistApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')

        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = TaskProjectCategoriesChecklist.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = TaskProjectCategoriesChecklist.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = TaskProjectCategoriesChecklist.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data
        p_ref=data.get('p_ref_id')
        org_ref=data.get('org_ref_id')
        tpcc_added_by_ref_user=data.get('tpcc_added_by_ref_user_id')
        pc_ref=data.get('pc_ref_id')
        pcc_ref=data.get('pcc_ref_id')
        opg_ref=data.get('opg_ref_id')
        tpcc_name=data.get('tpcc_name')
        tpcc_status=data.get('tpcc_status')
        tpcc_billable=data.get('tpcc_billable')
        tpcc_assignee_people_ref_u_id=data.get('tpcc_assignee_people_ref_u_id')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)        
        try:
            TaskProjectCategoriesChecklist.objects.create(p_ref_id=p_ref,
                                                            org_ref_id=org_ref,
                                                            tpcc_added_by_ref_user_id=tpcc_added_by_ref_user,
                                                            pc_ref_id=pc_ref,
                                                            pcc_ref_id=pcc_ref,
                                                           opg_ref_id=opg_ref,
                                                            tpcc_name=tpcc_name,
                                                            tpcc_status=tpcc_status,
                                                            tpcc_billable=tpcc_billable,
                                                            tpcc_assignee_people_ref_u_id=tpcc_assignee_people_ref_u_id)
            posts = TaskProjectCategoriesChecklist.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
        

    def put(self,request,pk):
        data = request.data
        
        p_ref=data.get('p_ref_id')
        org_ref=data.get('org_ref_id')
        tpcc_added_by_ref_user=data.get('tpcc_added_by_ref_user_id')
        pc_ref=data.get('pc_ref_id')
        pcc_ref=data.get('pcc_ref_id')
        opg_ref=data.get('opg_ref_id')
        tpcc_name=data.get('tpcc_name')
        tpcc_status=data.get('tpcc_status')
        tpcc_billable=data.get('tpcc_billable')
        tpcc_assignee_people_ref_u_id=data.get('tpcc_assignee_people_ref_u_id')
        try:
            TaskProjectCategoriesChecklist.objects.filter(id=pk).update(p_ref_id=p_ref,
                                                            org_ref_id=org_ref,
                                                            tpcc_added_by_ref_user_id=tpcc_added_by_ref_user,
                                                            pc_ref_id=pc_ref,
                                                            pcc_ref_id=pcc_ref,
                                                            opg_ref_id=opg_ref,
                                                            tpcc_name=tpcc_name,
                                                            tpcc_status=tpcc_status,
                                                            tpcc_billable=tpcc_billable,
                                                            tpcc_assignee_people_ref_u_id=tpcc_assignee_people_ref_u_id)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            
            

    def delete(self,request,pk):
        test = (0,{})    
        all_values = TaskProjectCategoriesChecklist.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class TimesheetMasterApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = TimesheetMaster.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = TimesheetMaster.objects.filter(id=id).values().order_by('-id')
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = TimesheetMaster.objects.all().values().order_by('-id')
            selected_page_no =1 
            page_number = request.GET.get('page')
            if page_number:
                selected_page_no = int(page_number)
            try:
                posts =TimesheetMaster.objects.all().values().order_by('-id')
                paginator = Paginator(posts,10)
                try:
                    page_obj = paginator.get_page(selected_page_no)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)
                return Response({'result':{'status':'Created','data':list(page_obj)}})
            except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
            

    def post(self,request):
        data = request.data
        tm_ref_user = data.get('tm_ref_user')
        ula_ref = data.get('ula_ref')
        org_ref = data.get('org_ref')
        tm_approver_ref_user = data.get('tm_approver_ref_user')
        tm_status = data.get('tm_status')
        tm_leave_holiday_conflict = data.get('tm_leave_holiday_conflict')
        tm_auto_approved = data.get('tm_auto_approved')
        tm_deadline_status = data.get('tm_deadline_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            TimesheetMaster.objects.create(
                tm_ref_user_id = tm_ref_user,
                ula_ref_id = ula_ref,
                org_ref_id = org_ref,
                tm_approver_ref_user_id = tm_approver_ref_user,
                tm_status = tm_status,
                tm_leave_holiday_conflict = tm_leave_holiday_conflict,
                tm_auto_approved = tm_auto_approved,
                tm_deadline_status = tm_deadline_status,
            )
            posts = TimesheetMaster.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        tm_ref_user = data.get('tm_ref_user')
        ula_ref = data.get('ula_ref')
        org_ref = data.get('org_ref')
        tm_approver_ref_user = data.get('tm_approver_ref_user')
        tm_status = data.get('tm_status')
        tm_leave_holiday_conflict = data.get('tm_leave_holiday_conflict')
        tm_auto_approved = data.get('tm_auto_approved')
        tm_deadline_status = data.get('tm_deadline_status')
        try:
        
            TimesheetMaster.objects.filter(id=pk).update(
                tm_ref_user_id = tm_ref_user,
                ula_ref_id = ula_ref,
                org_ref_id = org_ref,
                tm_approver_ref_user_id = tm_approver_ref_user,
                tm_status = tm_status,
                tm_leave_holiday_conflict = tm_leave_holiday_conflict,
                tm_auto_approved = tm_auto_approved,
                tm_deadline_status = tm_deadline_status,
                )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        all_values = TimesheetMaster.objects.filter(id=pk).delete()
        return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class TimesheetMasterDetailsApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        all_data = TimesheetMasterDetails.objects.filter(id=id).values().order_by('-id')
      
        if id:
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = TimesheetMasterDetails.objects.all().values().order_by('-id')
            selected_page_no =1 
            page_number = request.GET.get('page')
            if page_number:
                selected_page_no = int(page_number)
            try:
                posts =TimesheetMasterDetails.objects.all().values().order_by('-id')
                paginator = Paginator(posts,10)
                try:
                    page_obj = paginator.get_page(selected_page_no)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)
                return Response({'result':{'status':'Created','data':list(page_obj)}})
            except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
            # all_data = TimesheetMasterDetails.objects.all().values().order_by('-id')
            # return Response({'result':{'status':'GET','data':all_data}})

    def post(self,request):
        data = request.data
        tmd_ref_tm = data.get('tmd_ref_tm')
        tmd_ref_user = data.get('tmd_ref_user')
        org_ref = data.get('org_ref')
        c_ref = data.get('c_ref')
        p_ref = data.get('p_ref')
        tpcc_ref = data.get('tpcc_ref')
        ula_ref = data.get('ula_ref')
        tmd_approver_ref_user = data.get('tmd_approver_ref_user')
        tmd_timer_status = data.get('tmd_timer_status')
        tmd_description = data.get('tmd_description')
        tmd_status = data.get('tmd_status')
        tmd_halfday_status = data.get('tmd_halfday_status')
        tmd_leave_holiday_conflict = data.get('tmd_leave_holiday_conflict')
        tmd_auto_approved = data.get('tmd_auto_approved')
        tmd_deadline_status = data.get('tmd_deadline_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            TimesheetMasterDetails.objects.create(tmd_ref_user_id=tmd_ref_user,
                                                    org_ref_id=org_ref,
                                                    c_ref_id=c_ref,
                                                    p_ref_id=p_ref,
                                                    tpcc_ref_id=tpcc_ref,
                                                    ula_ref_id=ula_ref,
                                                    tmd_approver_ref_user_id=tmd_approver_ref_user,
                                                    tmd_timer_status=tmd_timer_status,
                                                    tmd_description=tmd_description,
                                                    tmd_status=tmd_status,
                                                    tmd_halfday_status=tmd_halfday_status,
                                                    tmd_leave_holiday_conflict=tmd_leave_holiday_conflict,
                                                    tmd_auto_approved=tmd_auto_approved,
                                                    tmd_deadline_status=tmd_deadline_status)
            posts = TimesheetMasterDetails.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def put(self,request,pk):
        data = request.data
        tmd_ref_tm = data.get('tmd_ref_tm')
        tmd_ref_user = data.get('tmd_ref_user')
        org_ref = data.get('org_ref')
        c_ref = data.get('c_ref')
        p_ref = data.get('p_ref')
        tpcc_ref = data.get('tpcc_ref')
        ula_ref = data.get('ula_ref')
        tmd_approver_ref_user = data.get('tmd_approver_ref_user')
        tmd_timer_status = data.get('tmd_timer_status')
        tmd_description = data.get('tmd_description')
        tmd_status = data.get('tmd_status')
        tmd_halfday_status = data.get('tmd_halfday_status')
        tmd_leave_holiday_conflict = data.get('tmd_leave_holiday_conflict')
        tmd_auto_approved = data.get('tmd_auto_approved')
        tmd_deadline_status = data.get('tmd_deadline_status')
        try:
            TimesheetMasterDetails.objects.filter(id=pk).update(
                tmd_ref_tm_id = tmd_ref_tm,
                tmd_ref_user_id = tmd_ref_user,
                org_ref_id = org_ref,
                c_ref_id = c_ref,
                p_ref_id = p_ref,
                tpcc_ref_id = tpcc_ref,
                ula_ref_id = ula_ref,
                tmd_approver_ref_user_id = tmd_approver_ref_user,
                tmd_timer_status = tmd_timer_status,
                tmd_description = tmd_description,
                tmd_status = tmd_status,
                tmd_halfday_status = tmd_halfday_status,
                tmd_leave_holiday_conflict = tmd_leave_holiday_conflict,
                tmd_auto_approved = tmd_auto_approved,
                tmd_deadline_status = tmd_deadline_status,
            )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            
            

    def delete(self,request,pk):
        test = (0,{}) 
        all_values = TimesheetMasterDetails.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class UserApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        role_name = request.query_params.get('filter')

        key = {'organization_id','page_number','data_per_page','pagination'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = request.query_params.get('organization_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')


        if 'filter' in request.query_params.keys():
            all_role_data =  UserRole.objects.filter(Q(organization_id=organization_id) & Q(user_role_name__istartswith='MANAGER')).values_list('id')
            all_data = CustomUser.objects.filter(Q(organization_id=organization_id) & Q(user_role_id__in= all_role_data)).values().order_by('-id')
            cuser_data = []
            for i in all_data:
                user_role_data =  UserRole.objects.get(id=i['user_role_id'])
                organization_data = Organization.objects.get(id=i['organization_id'])
                dic={
                    'id':i['id'],
                    'center_id':i['center_id'],
                    'user_role_id':i['user_role_id'],
                    'user_role_name':user_role_data.user_role_name,
                    'organization_id':i['organization_id'],
                    'organization_ namne ':organization_data.org_name,
                    'u_unique_id':i['u_unique_id'],
                    'u_org_code':i['u_org_code'],
                    'u_first_name':i['u_first_name'],
                    'u_last_name':i['u_last_name'],
                    'u_gender':i['u_gender'],
                    'u_marital_status':i['u_marital_status'],
                    'u_designation':i['u_designation'],
                    'u_date_of_joining':i['u_date_of_joining'],
                    'u_profile_photo':i['u_profile_photo'],
                    'u_profile_path':i['u_profile_path'],
                    'u_email':i['u_email'],
                    'u_phone_no':i['u_phone_no'],
                    'u_status':i['u_status'],
                    'u_created_from':i['u_created_from'],
                    'u_last_login':i['u_last_login'],
                    'u_login_token_key':i['u_login_token_key'],
                    'u_activation_status':i['u_activation_status'],
                    'u_profile_updated_status':i['u_profile_updated_status'],
                    'u_activation_link_sent_count':i['u_activation_link_sent_count'],
                    'u_activation_link':i['u_activation_link'],
                    'u_acc_expiry_date':i['u_acc_expiry_date'],
                    'u_is_first_user':i['u_is_first_user'],
                    'u_country':i['u_country'],
                    'u_state':i['u_state'],
                    'u_city':i['u_city'],
                    'u_address':i['u_address'],
                    'u_postal_code':i['u_postal_code'],
                    'u_dob':i['u_dob'],
                    'u_screen_lock_status':i['u_screen_lock_status'],
                    'tags':i['tags'],
                                    }
                if i['center_id']:
                    center_data = Center.objects.get(id=i['center_id'])
                    dic['center_name'] = center_data.center_name,

                cuser_data.append(dic)
            return Response({'result':{'status':'Get MANAGER data without pagination','data':cuser_data}})


        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = CustomUser.objects.filter(Q(organization_id=organization_id)).values().order_by('-id')
            cuser_data = []
            for i in all_data:
                user_role_data =  UserRole.objects.get(id=i['user_role_id'])
                
                organization_data = Organization.objects.get(id=i['organization_id'])
                dic={
                    'id':i['id'],
                    'center_id':i['center_id'],
                    'user_role_id':i['user_role_id'],
                    'user_role_name':user_role_data.user_role_name,
                    'organization_id':i['organization_id'],
                    'organization_ namne ':organization_data.org_name,
                    'u_unique_id':i['u_unique_id'],
                    'u_org_code':i['u_org_code'],
                    'u_first_name':i['u_first_name'],
                    'u_last_name':i['u_last_name'],
                    'u_gender':i['u_gender'],
                    'u_marital_status':i['u_marital_status'],
                    'u_designation':i['u_designation'],
                    'u_date_of_joining':i['u_date_of_joining'],
                    'u_profile_photo':i['u_profile_photo'],
                    'u_profile_path':i['u_profile_path'],
                    'u_email':i['u_email'],
                    'u_phone_no':i['u_phone_no'],
                    'u_status':i['u_status'],
                    'u_created_from':i['u_created_from'],
                    'u_last_login':i['u_last_login'],
                    'u_login_token_key':i['u_login_token_key'],
                    'u_activation_status':i['u_activation_status'],
                    'u_profile_updated_status':i['u_profile_updated_status'],
                    'u_activation_link_sent_count':i['u_activation_link_sent_count'],
                    'u_activation_link':i['u_activation_link'],
                    'u_acc_expiry_date':i['u_acc_expiry_date'],
                    'u_is_first_user':i['u_is_first_user'],
                    'u_country':i['u_country'],
                    'u_state':i['u_state'],
                    'u_city':i['u_city'],
                    'u_address':i['u_address'],
                    'u_postal_code':i['u_postal_code'],
                    'u_dob':i['u_dob'],
                    'u_screen_lock_status':i['u_screen_lock_status'],
                    'tags':i['tags'],
                                    }
                if i['center_id']:
                    center_data = Center.objects.get(id=i['center_id'])
                    dic['center_name'] = center_data.center_name,

                cuser_data.append(dic)
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = CustomUser.objects.filter(Q(organization_id=organization_id) & Q(id=id)).values().order_by('-id')
            cuser_data = []
            for i in all_data:
                user_role_data =  UserRole.objects.get(id=i['user_role_id'])
                organization_data = Organization.objects.get(id=i['organization_id'])
                dic={
                    'id':i['id'],
                    'center_id':i['center_id'],
                    'user_role_id':i['user_role_id'],
                    'user_role_name':user_role_data.user_role_name,
                    'organization_id':i['organization_id'],
                    'organization_ namne ':organization_data.org_name,
                    'u_unique_id':i['u_unique_id'],
                    'u_org_code':i['u_org_code'],
                    'u_first_name':i['u_first_name'],
                    'u_last_name':i['u_last_name'],
                    'u_gender':i['u_gender'],
                    'u_marital_status':i['u_marital_status'],
                    'u_designation':i['u_designation'],
                    'u_date_of_joining':i['u_date_of_joining'],
                    'u_profile_photo':i['u_profile_photo'],
                    'u_profile_path':i['u_profile_path'],
                    'u_email':i['u_email'],
                    'u_phone_no':i['u_phone_no'],
                    'u_status':i['u_status'],
                    'u_created_from':i['u_created_from'],
                    'u_last_login':i['u_last_login'],
                    'u_login_token_key':i['u_login_token_key'],
                    'u_activation_status':i['u_activation_status'],
                    'u_profile_updated_status':i['u_profile_updated_status'],
                    'u_activation_link_sent_count':i['u_activation_link_sent_count'],
                    'u_activation_link':i['u_activation_link'],
                    'u_acc_expiry_date':i['u_acc_expiry_date'],
                    'u_is_first_user':i['u_is_first_user'],
                    'u_country':i['u_country'],
                    'u_state':i['u_state'],
                    'u_city':i['u_city'],
                    'u_address':i['u_address'],
                    'u_postal_code':i['u_postal_code'],
                    'u_dob':i['u_dob'],
                    'u_screen_lock_status':i['u_screen_lock_status'],
                    'tags':i['tags'],
                                    }
                if i['center_id']:
                    center_data = Center.objects.get(id=i['center_id'])
                    dic['center_name'] = center_data.center_name,

                cuser_data.append(dic)
            return Response({'result':{'status':'GET by Id','data':cuser_data}})
        else:
            
            all_data = CustomUser.objects.filter(Q(organization_id=organization_id)).values().order_by('-id')
            cuser_data = []
            for i in all_data:
                user_role_data =  UserRole.objects.get(id=i['user_role_id'])
                organization_data = Organization.objects.get(id=i['organization_id'])
                dic={
                    'id':i['id'],
                    'center_id':i['center_id'],
                    'user_role_id':i['user_role_id'],
                    'user_role_name':user_role_data.user_role_name,
                    'organization_id':i['organization_id'],
                    'organization_ namne ':organization_data.org_name,
                    'u_unique_id':i['u_unique_id'],
                    'u_org_code':i['u_org_code'],
                    'u_first_name':i['u_first_name'],
                    'u_last_name':i['u_last_name'],
                    'u_gender':i['u_gender'],
                    'u_marital_status':i['u_marital_status'],
                    'u_designation':i['u_designation'],
                    'u_date_of_joining':i['u_date_of_joining'],
                    'u_profile_photo':i['u_profile_photo'],
                    'u_profile_path':i['u_profile_path'],
                    'u_email':i['u_email'],
                    'u_phone_no':i['u_phone_no'],
                    'u_status':i['u_status'],
                    'u_created_from':i['u_created_from'],
                    'u_last_login':i['u_last_login'],
                    'u_login_token_key':i['u_login_token_key'],
                    'u_activation_status':i['u_activation_status'],
                    'u_profile_updated_status':i['u_profile_updated_status'],
                    'u_activation_link_sent_count':i['u_activation_link_sent_count'],
                    'u_activation_link':i['u_activation_link'],
                    'u_acc_expiry_date':i['u_acc_expiry_date'],
                    'u_is_first_user':i['u_is_first_user'],
                    'u_country':i['u_country'],
                    'u_state':i['u_state'],
                    'u_city':i['u_city'],
                    'u_address':i['u_address'],
                    'u_postal_code':i['u_postal_code'],
                    'u_dob':i['u_dob'],
                    'u_screen_lock_status':i['u_screen_lock_status'],
                    'tags':i['tags'],
                                    }
                if i['center_id']:
                    center_data = Center.objects.get(id=i['center_id'])
                    dic['center_name'] = center_data.center_name,

                cuser_data.append(dic)
            data_pagination = EztimeAppPagination(cuser_data,page_number,data_per_page,request)

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

    def post(self,request):
        data = request.data
        u_first_name = data.get('u_first_name')  
        u_last_name = data.get('u_last_name')  
        u_gender = data.get('u_gender')  
        u_marital_status = data.get('u_marital_status')  
        u_phone_no        = data.get('u_phone_no')
        email         = data.get('email')
        password      = data.get('password')
        u_org_code = data.get('org_code')
        u_designation = data.get('u_designation')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
            if User.objects.filter(Q(username=email)|Q(email=email)).exists():
                return Response({'error': {'message':'User already exists'}})
            else:
                try:
                    create_user = User.objects.create_user(username=email,email=email,password=password)
                    user_create = CustomUser.objects.create(
                        user_created_by_id=create_user.id,
                        u_email=email,
                        u_designation=u_designation,
                        u_phone_no=u_phone_no,
                        u_org_code=u_org_code,
                        u_first_name=u_first_name,
                        u_last_name=u_last_name,
                        u_gender=u_gender,
                        u_marital_status=u_marital_status,
                        )
                    posts = CustomUser.objects.all().values().order_by('-id')
                    paginator = Paginator(posts,10)
                    try:
                        page_obj = paginator.get_page(selected_page_no)
                    except PageNotAnInteger:
                        page_obj = paginator.page(1)
                    except EmptyPage:
                        page_obj = paginator.page(paginator.num_pages)
                    return Response({'result':{'status':'Created','data':list(page_obj)}})
                except IntegrityError as e:
                    error_message = e.args
                    return Response({
                    'error':{'message':'DB error!',
                    'detail':error_message,
                    'status_code':status.HTTP_400_BAD_REQUEST,
                    }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data  
        u_first_name = data.get('first_name')  
        u_last_name = data.get('last_name')  
        u_gender = data.get('gender')  
        u_marital_status = data.get('marital_status')  
        u_phone_no        = data.get('phone_no')
        u_org_code = data.get('org_code')
        u_designation = data.get('designation')
        u_country =data.get('country')
        u_state =data.get('state')
        u_city =data.get('city')
        u_address =data.get('address')
        u_postal_code =data.get('postal_code')
        u_dob =data.get('dob')
        tags =data.get('tags')
        
        try:
            user_create = CustomUser.objects.filter(id=pk).update(
                u_first_name = u_first_name,
                u_last_name = u_last_name,
                u_gender = u_gender,
                u_marital_status = u_marital_status,
                u_phone_no = u_phone_no,
                u_org_code = u_org_code,
                u_designation = u_designation,
                u_country = u_country,
                u_state = u_state,
                u_city = u_city,
                u_address = u_address,
                u_postal_code = u_postal_code,
                u_dob = u_dob,
                tags=tags
                )

            try:
                profile_base64 = data.get('profile_base64')
                if profile_base64 != '':
                    user_data = CustomUser.objects.get(id=pk)
                    stored_path = StoreBase64ReturnPath(profile_base64, file_stored_path, project_base_url)
                    user_data.u_profile_path = stored_path
                    user_data.save()

            except:
                print("Profile base64")
            return Response({'result':{'status':'profile updated!'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)


    def delete(self,request,pk):
        test = (0,{})
        c_values = CustomUser.objects.filter(user_created_by_id=pk).delete()         
        u_values = User.objects.filter(id=pk).delete()
        if test == c_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class  PrefixSuffixApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')

        key = {'organization_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = request.query_params.get('organization_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = PrefixSuffix.objects.filter(organization_id=organization_id).values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = PrefixSuffix.objects.filter(Q(id=id) & Q(organization_id=organization_id)).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
               
                all_data = PrefixSuffix.objects.filter(Q(organization_id=organization_id) & (Q(prefix__icontains  = search_key)|Q(suffix__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = PrefixSuffix.objects.filter(organization_id=organization_id).values().order_by('-id')

            # all_data = PrefixSuffix.objects.all().values().order_by('-id')
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
           
    def post(self,request):
        data = request.data
        prefix = data.get('prefix')
        suffix = data.get('suffix')

       
        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        
        organization_id = data.get('organization_id')
        


        prefixsuffix_status=data.get('prefixsuffix_status')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            if PrefixSuffix.objects.filter(Q(prefix__iexact =prefix) & Q(organization_id=organization_id)).exists():
                return Response({
                    'error': {'message': 'prefix name already exists!',
                            'detail': 'prefix name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)

            if PrefixSuffix.objects.filter(Q(suffix__iexact =suffix) & Q(organization_id=organization_id)).exists():
                return Response({
                    'error': {'message': 'suffix name already exists!',
                            'detail': 'suffix name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)
            
            else:

                PrefixSuffix.objects.create(prefix=prefix,
                                            suffix=suffix,
                                            prefixsuffix_status=prefixsuffix_status,
                                            organization_id=organization_id
                                            )
                posts = PrefixSuffix.objects.filter(organization_id=organization_id).values().order_by('-id')
                paginator = Paginator(posts,10)
                try:
                    page_obj = paginator.get_page(selected_page_no)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)
                return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        prefix = data.get('prefix')
        suffix = data.get('suffix')
        prefixsuffix_status=data.get('prefixsuffix_status')
        
        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        
        organization_id = data.get('organization_id')

        try:
            if PrefixSuffix.objects.filter(Q(organization_id=organization_id) & ~Q(id=pk) & Q(prefix__iexact=prefix)).exists():
                return Response({
                    'error': {'message': 'prefix name already exists!',
                            'detail': 'prefix name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)

            if PrefixSuffix.objects.filter(Q(organization_id=organization_id) & ~Q(id=pk) & Q(suffix__iexact=suffix)).exists():
                return Response({
                    'error': {'message': 'suffix name already exists!',
                            'detail': 'suffix name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)

            else:

                PrefixSuffix.objects.filter(Q(organization_id=organization_id) & Q(id=pk)).update(prefix=prefix,
                                            suffix=suffix,
                                            prefixsuffix_status=prefixsuffix_status)
                return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})  
        all_values = PrefixSuffix.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class  CenterApiView(APIView):
    def get(self, request):
        id = request.query_params.get('id')

        key = {'organization_id', 'page_number', 'data_per_page', 'pagination'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response


        organization_id = request.query_params.get('organization_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')

        queryset = Center.objects.filter(organization_id=organization_id).values().order_by('-id')

        if id:
            queryset = queryset.filter(id=id)

        if pagination == 'FALSE':
            return Response({
                'result': {
                    'status': 'GET all without pagination',
                    'data': queryset
                }
            })

        if 'search_key' in request.query_params:
            search_key = request.query_params.get('search_key')
            queryset = queryset.filter(
                Q(center_name__icontains=search_key) |
                Q(center_status__icontains=search_key) |
                Q(c_timestamp__icontains=search_key)
            )

        paginated_data = paginate_data(queryset, page_number, data_per_page, request,organization_id)

        return Response({
            'result': {
                'status': 'GET ALL',
                **paginated_data
            }
        })

    def post(self,request):
        data = request.data
        
        center_name = data.get('center_name')
        sd = data.get('year_start_date')
        yed = data.get('year_end_date')
        center_status = data.get('center_status')

        year_start_date = time.mktime(datetime.datetime.strptime(sd, "%d/%m/%Y").timetuple())
        year_end_date = time.mktime(datetime.datetime.strptime(yed, "%d/%m/%Y").timetuple())

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = data.get('organization_id')

        if Center.objects.filter(Q(organization_id=organization_id) & Q(center_name__iexact=center_name)).exists():
            return Response({'error': {'message': 'Center name already exists!'}}, status=status.HTTP_400_BAD_REQUEST)

        try:
            Center.objects.create(
                organization_id=organization_id,
                center_name=center_name,
                year_start_date=year_start_date,
                year_end_date=year_end_date,
                center_status=center_status
            )
            return Response({'result': {'status': 'Created', 'message': 'Center created successfully'}})
        except IntegrityError as e:
            return Response({'error': {'message': 'DB error!', 'detail': str(e)}}, status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        center_name = data.get('center_name')
        sd = data.get('year_start_date')
        yed = data.get('year_end_date')
        center_status = data.get('center_status')
        
        year_start_date = time.mktime(datetime.datetime.strptime(sd, "%d/%m/%Y").timetuple())
        year_end_date = time.mktime(datetime.datetime.strptime(yed, "%d/%m/%Y").timetuple())

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = data.get('organization_id')

        try:
            if Center.objects.filter(Q(organization_id=organization_id) & ~Q(id=pk) & Q(center_name__iexact=center_name)).exists():
                return Response({'error': {'message': 'Center name already exists!'}}, status=status.HTTP_400_BAD_REQUEST)
            else:
                Center.objects.filter(Q(organization_id=organization_id) & Q(id=pk)).update(
                    center_name=center_name,
                    year_start_date=year_start_date,
                    year_end_date=year_end_date,
                    center_status=center_status
                )
                return Response({'result': {'status': 'Updated'}})
        except IntegrityError as e:
            return Response({'error': {'message': 'DB error!', 'detail': str(e)}}, status=status.HTTP_400_BAD_REQUEST)

            
    def delete(self,request,pk):
        test = (0,{})
        try:
            center = Center.objects.filter(id=pk).delete()
            # get_c_user = CustomUser.objects.filter(center_id=pk)
            # for k in get_c_user:
            #     people_deleted = People.objects.filter(user_id=k.id).delete()
            #     people = CustomUser.objects.filter(id=k.id).delete()
            #     center = Center.objects.filter(id=pk).delete()
            #     try:
            #         super_user_id = User.objects.filter(id=k.super_user_ref_id).delete()
            #     except IntegrityError as e:
            #         error_message = e.args
            #         return Response({
            #         'error':{'message':'Record not found!',
            #         'detail':error_message,
            #         'status_code':status.HTTP_400_BAD_REQUEST,
            #         }},status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'Something went wrong!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

      
        return Response({'result':{'status':'deleted'}})

    # ======   ======   ======   ======   ======   

        all_values = Center.objects.filter(id=pk).delete()
        if test == all_values:

            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class  PeopleApiView(GenericAPIView):
    def get(self,request):
        id = request.query_params.get('id')
        
        key = {'organization_id','page_number','data_per_page','pagination'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response


        organization_id = request.query_params.get('organization_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')

        if pagination == 'FALSE':

            all_data = People.objects.filter(organization_id=organization_id).values().order_by('-id')
            user_dat_list = []
            for i in all_data:
                user_data =  CustomUser.objects.get(id=i['user_id'])
                rep_user_data =  CustomUser.objects.get(id=i['user_id'])
                user_role_data = UserRole.objects.get(id=i['user_role_id'])
                tag_list =[]
                if i['tags'] != None:
                    for k in i['tags']:
                        tag_data = Tag.objects.get(id=k)
                        tag_dic ={
                            "id":tag_data.id,
                            "tag_name":tag_data.tag_name,
                            "added_date":tag_data.added_date,
                            "tage_status":tag_data.tage_status,
                        }
                        tag_list.append(tag_dic)
                    
                tag_list_converted = convert_tag_list_string(tag_list)

                dic_data = {
                    'id':i['user_id'],
                    'people_id':i['id'],
                    'user_reporting_manager_ref_id':i['user_reporting_manager_ref_id'] ,
                    'user_reporting_manager_name':rep_user_data.u_first_name ,
                    'user_reporting_manager_email':rep_user_data.u_email ,
                    'prefix_suffix_id': i['prefix_suffix_id'],
                    'organization_id':i['organization_id'],
                    'department_id': i['department_id'],     
                    'user_role_id': i['user_role_id'],
                    'user_role_name':user_role_data.user_role_name,
                    'organization_role_id': i['role_id'],
                    'cost_center_id':i['cost_center_id'],
                    'tags': tag_list,
                    'tag_list_converted':tag_list_converted,
                    'center_id':user_data.center_id,
                    'u_first_name':user_data.u_first_name ,
                    'u_last_name': user_data.u_last_name,
                    'u_email': user_data.u_email,
                    'u_marital_status':user_data.u_marital_status ,
                    'u_gender':user_data.u_gender ,
                    'u_designation':user_data.u_designation,
                    'u_date_of_joining':user_data.u_date_of_joining ,
                    'u_status': user_data.u_status,
                    'u_profile_path':user_data.u_profile_path ,
                    'u_org_code':user_data.u_org_code,
                }
                if i['prefix_suffix_id']:
                    prefix_data = PrefixSuffix.objects.get(id=i['prefix_suffix_id'])
                    dic_data['prefix']=prefix_data.prefix
                    dic_data['suffix']=prefix_data.suffix
                if i['department_id']:
                    department_data = OrganizationDepartment.objects.get(id=i['department_id'])
                    dic_data['department_name']=department_data.od_name

                if i['role_id']:
                    org_role_data = OrganizationRoles.objects.get(id=i['role_id'])
                    dic_data['organization_role_name'] =org_role_data.or_name
                
                if i['cost_center_id']:
                    cost_center_data = OrganizationCostCenters.objects.get(id=i['cost_center_id'])
                    dic_data['cost_center_name'] = cost_center_data.occ_cost_center_name

                if user_data.center_id:
                    center_data = Center.objects.get(id=user_data.center_id)
                    dic_data['center_name'] = center_data.center_name
                
                user_dat_list.append(dic_data)

            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET all without pagination','data':user_dat_list}})

        if id:
            all_data = People.objects.filter(Q(user_id=id) & Q(organization_id=organization_id)).values().order_by('-id')
            user_dat_list = []
            for i in all_data:
                user_data =  CustomUser.objects.get(id=i['user_id'])
                rep_user_data =  CustomUser.objects.get(id=i['user_id'])
                user_role_data = UserRole.objects.get(id=i['user_role_id'])
                tag_list =[]
                if i['tags'] != None:
                    for k in i['tags']:
                        tag_data = Tag.objects.get(id=k)
                        tag_dic ={
                            "id":tag_data.id,
                            "tag_name":tag_data.tag_name,
                            "added_date":tag_data.added_date,
                            "tage_status":tag_data.tage_status,
                        }
                        tag_list.append(tag_dic)
                    
                tag_list_converted = convert_tag_list_string(tag_list)

                dic_data = {
                    'id':i['user_id'],
                    'people_id':i['id'],
                    'user_reporting_manager_ref_id':i['user_reporting_manager_ref_id'] ,
                    'user_reporting_manager_name':rep_user_data.u_first_name ,
                    'user_reporting_manager_email':rep_user_data.u_email ,
                    'prefix_suffix_id': i['prefix_suffix_id'],
                    'organization_id':i['organization_id'],
                    'department_id': i['department_id'],     
                    'user_role_id': i['user_role_id'],
                    'user_role_name':user_role_data.user_role_name,
                    'organization_role_id': i['role_id'],
                    'cost_center_id':i['cost_center_id'],
                    'tags': tag_list,
                    'tag_list_converted':tag_list_converted,
                    'center_id':user_data.center_id,
                    'u_first_name':user_data.u_first_name ,
                    'u_last_name': user_data.u_last_name,
                    'u_email': user_data.u_email,
                    'u_marital_status':user_data.u_marital_status ,
                    'u_gender':user_data.u_gender ,
                    'u_designation':user_data.u_designation,
                    'u_date_of_joining':user_data.u_date_of_joining ,
                    'u_status': user_data.u_status,
                    'u_profile_path':user_data.u_profile_path ,
                    'u_org_code':user_data.u_org_code,
                }
                if i['prefix_suffix_id']:
                    prefix_data = PrefixSuffix.objects.get(id=i['prefix_suffix_id'])
                    dic_data['prefix']=prefix_data.prefix
                    dic_data['suffix']=prefix_data.suffix
                if i['department_id']:
                    department_data = OrganizationDepartment.objects.get(id=i['department_id'])
                    dic_data['department_name']=department_data.od_name

                if i['role_id']:
                    org_role_data = OrganizationRoles.objects.get(id=i['role_id'])
                    dic_data['organization_role_name'] =org_role_data.or_name
                
                if i['cost_center_id']:
                    cost_center_data = OrganizationCostCenters.objects.get(id=i['cost_center_id'])
                    dic_data['cost_center_name'] = cost_center_data.occ_cost_center_name

                if user_data.center_id:
                    center_data = Center.objects.get(id=user_data.center_id)
                    dic_data['center_name'] = center_data.center_name
                
                user_dat_list.append(dic_data)

            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':user_dat_list}})
        
        
        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
                Center
                
                # c_cuser = Center.objects.filter(Q(center_name__icontains  = search_key))
                # c_query = Q()
                # for c_entry in c_cuser:
                #     c_query = c_query | Q(center_id=c_entry.id)

                cuser = CustomUser.objects.filter(Q(center_id__center_name__icontains = search_key) | Q(u_first_name__icontains  = search_key) | Q(u_designation__icontains  = search_key) | Q(u_status__icontains  = search_key))
                query = Q()
                for entry in cuser:
                    query = query | Q(user_id=entry.id)

                r_cuser = UserRole.objects.filter(Q(user_role_name__icontains  = search_key))
                if 'ignore_super_admin' in request.query_params:
                    ignore_super_admin = request.query_params.get('ignore_super_admin')
                    if ignore_super_admin == 'TRUE':
                        r_cuser = r_cuser.exclude(user_role_name__istartswith="SUPER")

                r_query = Q()
                for r_entry in r_cuser:
                    r_query = r_query | Q(user_role_id=r_entry.id)

                print(query,"queryIN===search_key")
                print(r_query,"r_queryIN===search_key")
                if not query and not r_query:
                    print("1111111222222222===queryIN===search_key")
                    all_data =[]
                    
                else:
                    all_data = People.objects.filter(Q(organization_id=organization_id) & (query | r_query)).values().order_by('id')
                    print(all_data,"IN===search_key")
            else:
                all_data = People.objects.filter(organization_id=organization_id).values().order_by('id')
                print("else===search_key")

            
            user_dat_list = []
            for i in all_data:
                user_data =  CustomUser.objects.get(id=i['user_id'])
                rep_user_data =  CustomUser.objects.get(id=i['user_id'])
                user_role_data = UserRole.objects.get(id=i['user_role_id'])
                tag_list =[]
                if i['tags'] != None:
                    for k in i['tags']:
                        tag_data = Tag.objects.get(id=k)
                        tag_dic ={
                            "id":tag_data.id,
                            "tag_name":tag_data.tag_name,
                            "added_date":tag_data.added_date,
                            "tage_status":tag_data.tage_status,
                        }
                        tag_list.append(tag_dic)
                tag_list_converted = convert_tag_list_string(tag_list)
                dic_data = {
                    'id':i['user_id'],
                    'people_id':i['id'],
                    'user_reporting_manager_ref_id':i['user_reporting_manager_ref_id'] ,
                    'user_reporting_manager_name':rep_user_data.u_first_name ,
                    'user_reporting_manager_email':rep_user_data.u_email ,
                    'prefix_suffix_id': i['prefix_suffix_id'],
                    'organization_id':i['organization_id'],
                    'department_id': i['department_id'],
                    'user_role_id': i['user_role_id'],
                    'user_role_name':user_role_data.user_role_name,
                    'organization_role_id': i['role_id'],
                    'cost_center_id':i['cost_center_id'],
                    'tags': tag_list,
                    'tag_list_converted':tag_list_converted,
                    'center_id':user_data.center_id,                    
                    'u_first_name':user_data.u_first_name ,
                    'u_last_name': user_data.u_last_name,
                    'u_email': user_data.u_email,
                    'u_marital_status':user_data.u_marital_status ,
                    'u_gender':user_data.u_gender ,
                    'u_designation':user_data.u_designation,
                    'u_date_of_joining':user_data.u_date_of_joining ,
                    'u_status': user_data.u_status,
                    'u_profile_path':user_data.u_profile_path ,
                    'u_org_code':user_data.u_org_code,
                }
                if i['prefix_suffix_id']:
                    prefix_data = PrefixSuffix.objects.get(id=i['prefix_suffix_id'])
                    dic_data['prefix']=prefix_data.prefix
                    dic_data['suffix']=prefix_data.suffix
                if i['department_id']:
                    department_data = OrganizationDepartment.objects.get(id=i['department_id'])
                    dic_data['department_name']=department_data.od_name

                if i['role_id']:
                    org_role_data = OrganizationRoles.objects.get(id=i['role_id'])
                    dic_data['organization_role_name'] =org_role_data.or_name
                
                if i['cost_center_id']:
                    cost_center_data = OrganizationCostCenters.objects.get(id=i['cost_center_id'])
                    dic_data['cost_center_name'] = cost_center_data.occ_cost_center_name

                if user_data.center_id:
                    center_data = Center.objects.get(id=user_data.center_id)
                    dic_data['center_name'] = center_data.center_name
                
                user_dat_list.append(dic_data)
            data_pagination = EztimeAppPagination(user_dat_list,page_number,data_per_page,request)

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


    def post(self,request):
        data = request.data
        # name = data['name']
        prefix_suffix_id  = data['prefix_suffix_id']
        department_id= data['department_id']
        org_role_id= data['org_role_id']
        organization_id= data['organization_id']
        user_role_id = data['user_role_id']
        cost_center_id= data['cost_center_id']
        center_id = data['center_id']
        tags= data['tags']


        user_reporting_manager_ref_id=data['user_reporting_manager_ref_id']
        u_first_name= data['u_first_name']
        u_last_name= data['u_last_name']
        u_email= data['u_email']
        u_marital_status= data['u_marital_status']
        u_gender= data['u_gender']
        u_designation= data['u_designation']
        
        u_date_of_joining=data['u_date_of_joining']
        u_status=data['u_status']
        profile_base64  = data['profile_base64']
        u_org_code = data['u_org_code']

        doj = time.mktime(datetime.datetime.strptime(u_date_of_joining, "%d/%m/%Y").timetuple())


        try:
            create_super_user = User.objects.create_user(username=u_email,email=u_email)

            user_create = CustomUser.objects.create(
                    center_id=center_id,
                    organization_id=organization_id,
                    
                    super_user_ref_id=create_super_user.id,
                    u_email=u_email,
                    u_designation=u_designation,
                    # u_phone_no=u_phone_no,
                    # u_org_code=u_org_code,
                    u_first_name=u_first_name,
                    u_last_name=u_last_name,
                    u_gender=u_gender,
                    u_marital_status=u_marital_status,
                    u_date_of_joining=doj,
                    u_status=u_status,
                    user_role_id=user_role_id,
                    )
                
            people_data = People.objects.create(
                        user_reporting_manager_ref_id = user_reporting_manager_ref_id,
                        user_id = user_create.id,
                        organization_id=organization_id,
                    
                        prefix_suffix_id = prefix_suffix_id,
                        department_id = department_id,
                        user_role_id=user_role_id,
                        role_id = org_role_id,
                        cost_center_id = cost_center_id,
                        tags = tags,
                        )

            file_stored_path = '/eztime/django/site/media/photo/'
            project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
            print(profile_base64,'profile_base64===>')
            if profile_base64 != '':
                print("In_profile_base64")
                stored_path = StoreBase64ReturnPath(profile_base64, file_stored_path, project_base_url)
                user_create.u_profile_path = stored_path
                user_create.save()


            # posts = People.objects.all().values().order_by('-id')
            
            return Response({'result':{'status':'User Created'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        prefix_suffix_id  = data['prefix_suffix_id']
        department_id= data['department_id']
        org_role_id= data['org_role_id']
        organization_id= data['organization_id']
        user_role_id = data['user_role_id']
        cost_center_id= data['cost_center_id']
        center_id = data['center_id']
        tags= data['tags']


        user_reporting_manager_ref_id=data['user_reporting_manager_ref_id']
        u_first_name= data['u_first_name']
        u_last_name= data['u_last_name']
        u_email= data['u_email']
        u_marital_status= data['u_marital_status']
        u_gender= data['u_gender']
        u_designation= data['u_designation']
        
        u_date_of_joining=data['u_date_of_joining']
        u_status=data['u_status']
        profile_base64  = data['profile_base64']
        u_org_code = data['u_org_code']


        doj = time.mktime(datetime.datetime.strptime(u_date_of_joining, "%d/%m/%Y").timetuple())

        try:
            data = CustomUser.objects.get(id=pk)
            super_user = User.objects.get(id=data.super_user_ref_id)
            print(u_email,'u_email',super_user.username,'super_user.username')

            if u_email == super_user.username:
                print('Email_exists')
            else:

                get_people_data = CustomUser.objects.get(id=pk)
                if get_people_data.organization_id != organization_id:
                    if Organization.objects.filter(Q(conctact_person_email = u_email)).exists():

                        return Response({
                            'error':{'message':'You cannot able to change organization',
                            'detail':"Becasue you are a contact person of the organization",
                            'status_code':status.HTTP_400_BAD_REQUEST,
                            }},status=status.HTTP_400_BAD_REQUEST)

                create_super_user = User.objects.filter(id=data.super_user_ref_id).update(username=u_email,email=u_email)

            user_create = CustomUser.objects.filter(id=pk).update(
                    center_id=center_id,
                    # organization_id=organization_id,
                    
                    super_user_ref_id=super_user.id,
                    u_email=u_email,
                    u_designation=u_designation,
                    # u_phone_no=u_phone_no,
                    # u_org_code=u_org_code,
                    u_first_name=u_first_name,
                    u_last_name=u_last_name,
                    u_gender=u_gender,
                    u_marital_status=u_marital_status,
                    u_date_of_joining=doj,
                    u_status=u_status,
                    user_role_id=user_role_id,
                    )
            print(data,'data==allll')
            people_data = People.objects.filter(user_id=pk).update(
                        user_reporting_manager_ref_id = user_reporting_manager_ref_id,
                        # organization_id=organization_id,
                        # user_id = user_create.id,
                        prefix_suffix_id = prefix_suffix_id,
                        department_id = department_id,
                        user_role_id=user_role_id,
                        # role_id = org_role_id,
                        cost_center_id = cost_center_id,
                        tags = tags,
                        )

            file_stored_path = '/eztime/django/site/media/photo/'
            project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
                
            if profile_base64 != '':
                user_data = CustomUser.objects.get(id=pk)
                stored_path = StoreBase64ReturnPath(profile_base64, file_stored_path, project_base_url)
                user_data.u_profile_path = stored_path
                user_data.save()



 
            return Response({'result':{'status':'User Updated'}})

        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
        
        
    def delete(self,request,pk):
        # res = GetCheckPermission(request)
        # if res[0] == 2:
        #     return res[1]
        test = (0,{})
        try:
            people_data = People.objects.get(id=pk)
            get_c_user = CustomUser.objects.get(id=people_data.user_id)
            
            people = People.objects.filter(id=pk).delete()
            people = CustomUser.objects.filter(id=people_data.user_id).delete()
            super_user_id = User.objects.filter(id=get_c_user.super_user_ref_id).delete()
            # all_values = CustomUser.objects.filter(id=pk).delete()
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

        if test == super_user_id:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class  TagApiView(APIView):
    def get(self,request):
        key = {'organization_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        id = request.query_params.get('id')
        organization_id = request.query_params.get('organization_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
    
        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = Tag.objects.filter(organization_id=organization_id).values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = Tag.objects.filter(Q(id=id) & Q(organization_id=organization_id)).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
              
                all_data = Tag.objects.filter(Q(organization_id=organization_id) & (Q(tag_name__icontains  = search_key)|Q(added_date__icontains  = search_key)|Q(tage_status__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = Tag.objects.filter(organization_id=organization_id).values().order_by('-id')

            # all_data = Tag.objects.all().values().order_by('-id')
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



    def post(self,request):
        data = request.data
        tag_name = data.get('tag_name')
        tage_status = data.get('tage_status')

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = data.get('organization_id')

        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            if Tag.objects.filter(Q(tag_name__iexact =tag_name) & Q(organization_id=organization_id)).exists():
                return Response({
                    'error': {'message': 'Tag name  already exists!',
                            'detail': 'Tag name  cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)
            else:
                Tag.objects.create(tag_name=tag_name,
                                        tage_status=tage_status,
                                        organization_id=organization_id)


                posts = Tag.objects.filter(organization_id=organization_id).values().order_by('-id')
                paginator = Paginator(posts,10)
                try:
                    page_obj = paginator.get_page(selected_page_no)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)
                return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        tag_name = data.get('tag_name')
        tage_status=data.get('tage_status')
        
        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = data.get('organization_id')

        try:
            if Tag.objects.filter(Q(organization_id=organization_id) & ~Q(id=pk) & Q(tag_name__iexact=tag_name)).exists():
                return Response({
                    'error': {'message': 'Tag name already exists!',
                            'detail': 'Tag name cannot be duplicated',
                            'status_code': status.HTTP_400_BAD_REQUEST,
                            }}, status=status.HTTP_400_BAD_REQUEST)

            else:
                Tag.objects.filter(Q(organization_id=organization_id) & Q(id=pk)).update(tag_name=tag_name,tage_status=tage_status
                                        )
                return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})   
        all_values = Tag.objects.filter(id=pk).delete()
        
        people_doc = People.objects.all()

        for l in people_doc:
            if l.tags != None and l.tags != "None":
                if len(l.tags) >= 1:
                    for r in l.tags:
                        if r == pk:
                            l.tags.remove(pk)
                            People.objects.filter(id=l.id).update(tags=l.tags)
                        else:
                            print("tags",pk)
                            
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class  TimeSheetApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        if id:
            all_data = TimeSheet.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = TimeSheet.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET','data':all_data}})

    def post(self,request):
        data = request.data
        client  = data.get('client_id')
        project= data.get('project_id')
        task= data.get('task_id')
        time_spent= data.get('time_spent')
        description= data.get('description')
        timesheet_status= data.get('timesheet_status')
        tdt= data.get('timesheet_date')
        timesheet_date_timestamp = time.mktime(datetime.datetime.strptime(tdt, "%d/%m/%Y").timetuple())
        print(timesheet_date_timestamp,'stamppppppppppppppp')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            TimeSheet.objects.create(client_id=client,
                                    project_id=project,
                                    task_id=task,
                                    time_spent=time_spent,
                                    description=description,
                                    timesheet_status=timesheet_status,
                                    timesheet_date_timestamp=timesheet_date_timestamp,)
            posts = TimeSheet.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        client  = data.get('client_id')
        project= data.get('project_id')
        task= data.get('task_id')
        time_spent= data.get('time_spent')
        description= data.get('description')
        timesheet_status= data.get('timesheet_status')
        tdt= data.get('timesheet_date')
        timesheet_date_timestamp = time.mktime(datetime.datetime.strptime(tdt, "%d/%m/%Y").timetuple())
        print(timesheet_date_timestamp,'stamppppppppppppppp')
        try:
            TimeSheet.objects.filter(id=pk).update(client_id=client,
                                    project_id=project,
                                    task_id=task,
                                    time_spent=time_spent,
                                    description=description,
                                    timesheet_status=timesheet_status,
                                    timesheet_date_timestamp=timesheet_date_timestamp,
                                        )
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = TimeSheet.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class  MasterLeaveTypesApiView(APIView):
    
    def get(self,request):
        key = {'organization_id'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = request.query_params.get('organization_id')

        if 'center_id' in request.query_params.keys():
            center_id = request.query_params.get('center_id')
            all_data = MasterLeaveTypes.objects.filter(Q(organization_id=organization_id) & Q(leave_applicable_for_id=center_id)).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})

        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = MasterLeaveTypes.objects.filter(Q(organization_id=organization_id)).values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = MasterLeaveTypes.objects.filter(Q(organization_id=organization_id) & Q(id=id)).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
               
                all_data = MasterLeaveTypes.objects.filter(Q(organization_id=organization_id) & (Q(leave_type__icontains  = search_key)| Q(leave_title__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = MasterLeaveTypes.objects.filter(Q(organization_id=organization_id)).values().order_by('-id')

            # all_data = MasterLeaveTypes.objects.all().values().order_by('-id')
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

    def post(self,request):
        data = request.data

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = data['organization_id']
        leave_title = data['leave_title']
        description = data['description']
        accrude_monthly = data['accrude_monthly']
        monthly_leaves = data['monthly_leaves']
        yearly_leaves = data['yearly_leaves']
        carry_forward_per = data['carry_forward_per']
        gracefull_days = data['gracefull_days']
        encashment = data['encashment']
        max_encashments = data['max_encashments']
        leave_applicable_for = data['leave_applicable_for']


        if max_encashments != "":
            if max_encashments > 0:
                max_encashments_value = max_encashments
            else: 
                max_encashments_value = 0
        else:
            max_encashments_value = 0

        if gracefull_days != "": 
            if gracefull_days > 0:
                gracefull_days_value = gracefull_days
            else:
                gracefull_days_value = 0
        else:
            gracefull_days_value = 0
        if accrude_monthly == True:
            total_leaves = float(monthly_leaves) + float(max_encashments_value) + float(gracefull_days_value)
        elif accrude_monthly == False:
            print(yearly_leaves,'yearly_leaves=====>')
            if yearly_leaves != "" and int(yearly_leaves) > 0:
                print("yearly_leaves===> if")
                total_leaves = float(yearly_leaves) + float(max_encashments_value) + float(gracefull_days_value)
                print(total_leaves,'total_leaves=====> if')
            else:
                print("yearly_leaves===> else")
                total_leaves = float(max_encashments_value) + float(gracefull_days_value)
                print(total_leaves,'total_leaves=====> else')
        else:
            return Response({
                'error':{'message':'Master leave type should have accrude_monthly flag',
                'hint':'Check the Master leave',
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
        # if  accrude_monthly == True:
        #     total_leaves = float(monthly_leaves) + float(max_encashments_value) + float(gracefull_days_value)

        # else:
        #     if yearly_leaves > 0:
        #         total_leaves = float(yearly_leaves) + float(max_encashments_value) + float(gracefull_days_value)
            
        #     else:
        #         total_leaves =  float(max_encashments_value) + float(gracefull_days_value)

        

        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        
   
        print(total_leaves,'total_leaves===>')
        try:
            MasterLeaveTypes.objects.create(
                organization_id=organization_id,
                no_of_leaves = total_leaves,
                leave_title = leave_title,
                description = description,
                accrude_monthly = accrude_monthly,
                monthly_leaves = monthly_leaves,
                yearly_leaves = yearly_leaves,
                carry_forward_per = carry_forward_per,
                gracefull_days = gracefull_days,
                encashment = encashment,
                max_encashments = max_encashments,
                leave_applicable_for_id = leave_applicable_for,
            )
            posts = MasterLeaveTypes.objects.filter(organization_id=organization_id).values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        leave_title = data['leave_title']
        description = data['description']
        accrude_monthly = data['accrude_monthly']
        monthly_leaves = data['monthly_leaves']
        yearly_leaves = data['yearly_leaves']
        carry_forward_per = data['carry_forward_per']
        gracefull_days = data['gracefull_days']
        encashment = data['encashment']
        max_encashments = data['max_encashments']
        leave_applicable_for = data['leave_applicable_for']
        
        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = data['organization_id']

        if max_encashments != "":
            if max_encashments > 0:
                max_encashments_value = max_encashments
            else: 
                max_encashments_value = 0
        else:
            max_encashments_value = 0

        if gracefull_days != "": 
            if gracefull_days > 0:
                gracefull_days_value = gracefull_days
            else:
                gracefull_days_value = 0
        else:
            gracefull_days_value = 0
        if accrude_monthly == True:
            total_leaves = float(monthly_leaves) + float(max_encashments_value) + float(gracefull_days_value)
        elif accrude_monthly == False:
            print(yearly_leaves,'yearly_leaves=====>')
            if yearly_leaves != "" and int(yearly_leaves) > 0:
                print("yearly_leaves===> if")
                total_leaves = float(yearly_leaves) + float(max_encashments_value) + float(gracefull_days_value)
                print(total_leaves,'total_leaves=====> if')
            else:
                print("yearly_leaves===> else")
                total_leaves = float(max_encashments_value) + float(gracefull_days_value)
                print(total_leaves,'total_leaves=====> else')
        else:
            return Response({
                'error':{'message':'Master leave type should have accrude_monthly flag',
                'hint':'Check the Master leave',
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)

        try:
            MasterLeaveTypes.objects.filter(Q(organization_id=organization_id) & Q(id=pk)).update(
                no_of_leaves = total_leaves,
                leave_title = leave_title,
                description = description,
                accrude_monthly = accrude_monthly,
                monthly_leaves = monthly_leaves,
                yearly_leaves = yearly_leaves,
                carry_forward_per = carry_forward_per,
                gracefull_days = gracefull_days,
                encashment = encashment,
                max_encashments = max_encashments,
                leave_applicable_for_id = leave_applicable_for,
            )
                                        
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})
        all_values = MasterLeaveTypes.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class  BalanceApiView(APIView):
    def get(self, request):
        user_id = request.query_params.get('user_id')
        days = request.query_params.get('days')
        leave_type_id = request.query_params.get('leave_type_id')
        cuser = CustomUser.objects.get(id=user_id)
        
        if user_id:
            try:
                center_leave = MasterLeaveTypes.objects.get(Q(leave_applicable_for_id=cuser.center_id) & Q(id=leave_type_id))
            except ObjectDoesNotExist:
                return Response({
                    'error': {
                        'message': 'Record not found!',
                        'status_code': status.HTTP_404_NOT_FOUND,
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            now_date = datetime.datetime.today()
            last_day = calendar.monthrange(now_date.year, now_date.month)[1]
            end_of_month_date = datetime.date(now_date.year, now_date.month, last_day)
            end_of_month_datetime = datetime.datetime.combine(end_of_month_date, datetime.time.min)
            end_of_month_timestamp = int(end_of_month_datetime.timestamp())

            total_leaves_taken = 0
            all_data = leaveApplication.objects.filter(Q(leave_type_id=leave_type_id) & Q(user_id=user_id) & Q(leaveApplication_from_date__lte=end_of_month_timestamp)).values().order_by('-id')
            for t in all_data:
                if t['approved_state'] != 'DECLINED':
                    total_leaves_taken = total_leaves_taken + float(t['days'])


                

            balance = 0
            monthly_leaves_left = 0
            result_dic = {'status': 'GET BY USER_ID'}
            
            if center_leave.accrude_monthly == True:
                monthly_leaves = center_leave.monthly_leaves
                no_of_leaves = center_leave.no_of_leaves
                
                if monthly_leaves != '' and no_of_leaves != '' and monthly_leaves is not None and no_of_leaves is not None:
                    # total_leaves_i_have = float(monthly_leaves) + float(no_of_leaves)
                    # print(float(total_leaves_i_have), 'total_leaves_i_have -', float(total_leaves_taken), ' total_leaves_taken')
                    
                    total_leaves_left = float(no_of_leaves) - float(total_leaves_taken)
                    
                    if total_leaves_left > 0:
                        if days and total_leaves_left:
                            if float(total_leaves_left) >= float(days):
                                balance = float(total_leaves_left) - float(days)
                                result_dic['accrude_monthly'] = "accrude monthly leave is added to total leaves"
                                result_dic['alloted_leaves'] = float(no_of_leaves)
                                result_dic['total_leaves_left_previously'] = float(total_leaves_left)
                                result_dic['used_leaves'] = float(no_of_leaves) - float(balance)
                                result_dic['balance_days'] = balance
                            else:
                                return Response({
                                    'error': {
                                        'message': 'You are applying for ' + str(days) + " leave, but you have " + str(float(total_leaves_left)) + " leaves left",
                                        'total_leaves_taken': float(total_leaves_taken),
                                        'total_leaves_left': float(total_leaves_left),
                                        'accrude_leaves':'Monthly leave is added to total leaves',
                                        'total_leaves':'Balance leaves ' + str(total_leaves_left) + " + accrude monthly leaves " + str(monthly_leaves) + " = "+str(balance),
                                        'status_code': status.HTTP_404_NOT_FOUND,
                                    }
                                }, status=status.HTTP_404_NOT_FOUND)
                        else:
                            return Response({
                                'error': {
                                    'message': 'Days or total leaves left not provided.',
                                    'status_code': status.HTTP_404_NOT_FOUND,
                                }
                            }, status=status.HTTP_404_NOT_FOUND)
                    else:
                        if total_leaves_left < 0:
                            message1 = "There is an issue with the balance leave, whether you are sending it now or previously."
                        else:
                            message1 = "Balance leave working fine"

                        return Response({
                            'error': {
                                'message': 'You do not have enough leaves left to apply',
                                'total_leaves_you_have': float(no_of_leaves),
                                'total_leaves_taken': float(total_leaves_taken),
                                'total_leaves_left': float(total_leaves_left),
                                'hint': message1,
                                'insternal':'1',
                                'status_code': status.HTTP_404_NOT_FOUND,
                            }
                        }, status=status.HTTP_404_NOT_FOUND)
                else:
                    return Response({
                        'error': {
                            'message': 'Invalid monthly_leaves or no_of_leaves values.',
                            'status_code': status.HTTP_404_NOT_FOUND,
                        }
                    }, status=status.HTTP_404_NOT_FOUND)

            if center_leave.accrude_monthly == False:
                yearly_leaves = center_leave.yearly_leaves
                no_of_leaves = center_leave.no_of_leaves
                
                if yearly_leaves != '' and no_of_leaves != '' and yearly_leaves is not None and no_of_leaves is not None:
                    # total_leaves_i_have = float(yearly_leaves) + float(no_of_leaves)
                    total_leaves_left = float(no_of_leaves) - float(total_leaves_taken)
                    
                    if total_leaves_left > 0:
                        if float(total_leaves_left) >= float(days):
                            balance = float(total_leaves_left) - float(days)
                            result_dic['accrude_yearly'] = "accrude yearly leave is added to total leaves"
                            result_dic['alloted_leaves'] = float(no_of_leaves)
                            result_dic['total_leaves_left_previously'] = float(total_leaves_left)
                            result_dic['used_leaves'] = float(no_of_leaves) - float(balance)
                            result_dic['balance_days'] = balance
                        else:
                            return Response({
                                'error': {
                                    'message': 'You are applying for ' + str(days) + " leave, but you have " + str(total_leaves_left) + " leaves left",
                                    'total_leaves_taken': float(total_leaves_taken),
                                    'total_leaves_left': float(total_leaves_left),
                                    'accrude_leaves':'Yearly leave is added to total leaves',
                                    'total_leaves':'Balance leaves ' + str(total_leaves_left) + " + accrude yearly leaves " + str(yearly_leaves) + " = "+str(balance),
                                    'status_code': status.HTTP_404_NOT_FOUND,
                                }
                            }, status=status.HTTP_404_NOT_FOUND)
                    else:
                        return Response({
                            'error': {
                                'message': 'You do not have enough leaves left to apply',
                                'total_leaves_you_have': float(no_of_leaves),
                                'total_leaves_taken': float(total_leaves_taken),
                                'total_leaves_left': float(total_leaves_left),
                                'insternal':'2',
                                'status_code': status.HTTP_404_NOT_FOUND,
                            }
                        }, status=status.HTTP_404_NOT_FOUND)
                else:
                    return Response({
                        'error': {
                            'message': 'Invalid yearly_leaves or no_of_leaves values.',
                            'status_code': status.HTTP_404_NOT_FOUND,
                        }
                    }, status=status.HTTP_404_NOT_FOUND)

            return Response({'result': result_dic})

        else:
            return Response({
                'error': {
                    'message': 'Enter valid user id',
                    'status_code': status.HTTP_404_NOT_FOUND,
                }
            }, status=status.HTTP_404_NOT_FOUND)
    # def get(self,request):
    #     user_id = request.query_params.get('user_id')
    #     days = request.query_params.get('days')
    #     leave_type_id = request.query_params.get('leave_type_id')
    #     cuser = CustomUser.objects.get(id=user_id)
    #     if user_id:
    #         try:
    #             center_leave = MasterLeaveTypes.objects.get(Q(leave_applicable_for_id=cuser.center_id) & Q(id=leave_type_id))
    #         except ObjectDoesNotExist:
    #         # do something
    #             return Response({
    #             'error':{'message':'Record not found!',
    #             'status_code':status.HTTP_404_NOT_FOUND,
    #             }},status=status.HTTP_404_NOT_FOUND)

    #         total_leaves_taken = 0
    #         all_data = leaveApplication.objects.filter( Q(leave_type_id=leave_type_id) & Q(user_id=user_id)).values().order_by('-id')
    #         for t in  all_data:
    #             total_leaves_taken = total_leaves_taken + float(t['days'])

    #         balance = 0
    #         monthly_leaves_left = 0
    #         result_dic = {'status':'GET BY USER_ID'}
    #         if center_leave.accrude_monthly == True:
    #             total_leaves_i_have = float(center_leave.monthly_leaves) + float(center_leave.no_of_leaves)
    #             print(float(total_leaves_i_have), 'total_leaves_i_have -', float(total_leaves_taken), ' total_leaves_taken')
    #             total_leaves_left = float(total_leaves_i_have) - float(total_leaves_taken)
    #             if total_leaves_left > 0:
    #                 if days and total_leaves_left:
    #                     if float(total_leaves_left) >= float(days):
    #                         balance = float(total_leaves_left) - float(days)
    #                         result_dic['accrude_monthly'] = "accrude monthly leave is added to total leaves"
    #                         result_dic['alloted_leaves'] = float(total_leaves_i_have)
    #                         result_dic['total_leaves_left_previously'] = float(total_leaves_left)
    #                         result_dic['used_leaves'] = float(total_leaves_i_have) - float(balance)
    #                         result_dic['balance_days'] = balance
    #                     else:
    #                         return Response({
    #                             'error': {
    #                                 'message': 'You are applying for ' + str(days) + " leave But, you have left with " + str(total_leaves_left) + " leaves",
    #                                 'total_leaves_taken': float(total_leaves_taken),
    #                                 'total_leaves_left': float(total_leaves_left),
    #                                 'status_code': status.HTTP_404_NOT_FOUND,
    #                             }
    #                         }, status=status.HTTP_404_NOT_FOUND)
    #                 else:
    #                     return Response({
    #                         'error': {
    #                             'message': 'Days or total leaves left not provided.',
    #                             'status_code': status.HTTP_404_NOT_FOUND,
    #                         }
    #                     }, status=status.HTTP_404_NOT_FOUND)
    #             else:
    #                 # total_leaves_left = 0
    #                 if total_leaves_left < 0:
    #                     message1 = "There is a issue in balance leave, what you are sending now or previously"
    #                 else:
    #                     message1 = "Balance leave working fine"

    #                 return Response({
    #                     'error':{'message':'You do not have enough leaves left to apply',
    #                     'total_leaves_taken':float(total_leaves_taken),
    #                     'total_leaves_left': float(total_leaves_left),
    #                     'hint':message1,
    #                     'status_code':status.HTTP_404_NOT_FOUND,
    #                     }},status=status.HTTP_404_NOT_FOUND)

    #         if center_leave.accrude_monthly == False:
    #             total_leaves_i_have = float(center_leave.yearly_leaves) +  float(center_leave.no_of_leaves)
    #             total_leaves_left = float(total_leaves_i_have) - float(total_leaves_taken)
    #             if total_leaves_left > 0:
    #                 if float(total_leaves_left) >= float(days):
    #                         balance = float(total_leaves_left) - float(days)
    #                         result_dic['accrude_yearly'] = "accrude yearly leave is added to total leaves"
    #                         result_dic['alloted_leaves'] = float(total_leaves_i_have)
    #                         result_dic['total_leaves_left_previously'] = float(total_leaves_left)
    #                         result_dic['used_leaves'] = float(total_leaves_i_have) - float(balance)
    #                         result_dic['balance_days'] = balance
    #                 else:
    #                     return Response({
    #                         'error':{'message':'You are applying for '+str(days) + " leave But, you have left with " + str(total_leaves_left) +" leaves",
    #                         'total_leaves_taken':float(total_leaves_taken),
    #                         'total_leaves_left': float(total_leaves_left),
    #                         'status_code':status.HTTP_404_NOT_FOUND,
    #                         }},status=status.HTTP_404_NOT_FOUND)
    #             else:
    #                 return Response({
    #                     'error':{'message':'You do not have enough leaves left to apply',
    #                     'total_leaves_taken':float(total_leaves_taken),
    #                     'total_leaves_left': float(total_leaves_left),
    #                     'status_code':status.HTTP_404_NOT_FOUND,
    #                     }},status=status.HTTP_404_NOT_FOUND)

           
    #         return Response({'result':result_dic})

    #     else:
    #         return Response({
    #             'error':{'message':'Enter valid user id',
    #             'status_code':status.HTTP_404_NOT_FOUND,
    #             }},status=status.HTTP_404_NOT_FOUND)
                
from django.db.models import Q, Sum

@method_decorator([AutorizationRequired], name='dispatch')
class  leaveDetailsApiView(APIView):
    def get(self, request):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
        
        key = {'organization_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = request.query_params.get('organization_id')
        id = request.query_params.get('id')
        user_id = request.query_params.get('user_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')

        if not all([page_number, data_per_page]):
            return Response({
                'error': {
                    'message': 'page_number or data_per_page parameter missing!',
                    'status_code': status.HTTP_404_NOT_FOUND,
                }
            }, status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')

        if user_id:
            complete_data = []
            try:
                all_data = leaveApplication.objects.filter(Q(user_id=user_id) & Q(organization_id=organization_id))
            except leaveApplication.DoesNotExist:
                return Response({
                    'error': {
                        'message': 'Leave application does not exist!',
                        'hint': 'You have not applied for any leaves',
                        'status_code': status.HTTP_404_NOT_FOUND,
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            for c in all_data:
                try:
                    master_leave = MasterLeaveTypes.objects.get(Q(organization_id=organization_id) & Q(id=c.leave_type_id))
                except MasterLeaveTypes.DoesNotExist:
                    return Response({
                        'error': {
                            'message': 'Leave application does not exist!',
                            'hint': 'You have not applied for any leaves',
                            'status_code': status.HTTP_404_NOT_FOUND,
                        }
                    }, status=status.HTTP_404_NOT_FOUND)

                print(master_leave.leave_title, 'master_leave.leave_title')
                leave_from = datetime.datetime.fromtimestamp(float(c.leaveApplication_from_date)).strftime('%d/%m/%Y')
                leave_to = datetime.datetime.fromtimestamp(float(c.leaveApplication_to_date)).strftime('%d/%m/%Y')

                all_dic = {
                    'leave_type_id': c.leave_type_id,
                    'leave_type': master_leave.leave_title,
                    'from_date': leave_from,
                    'to_date': leave_to,
                    'days': c.days,
                    'expires': leave_to,
                    'approved_state': c.approved_state
                }
                complete_data.append(all_dic)

            leave_type = MasterLeaveTypes.objects.filter(Q(organization_id=organization_id))
            cuser = CustomUser.objects.get(id=user_id)

            leave_balance_list = []
            for i in leave_type:
                print(cuser.center_id, 'cuser.center_id', i.id, 'i.id')
                now_date = datetime.datetime.today()
                last_day = calendar.monthrange(now_date.year, now_date.month)[1]
                end_of_month_date = datetime.date(now_date.year, now_date.month, last_day)
                end_of_month_datetime = datetime.datetime.combine(end_of_month_date, datetime.time.min)
                end_of_month_timestamp = int(end_of_month_datetime.timestamp())

                try:
                    center_leave = MasterLeaveTypes.objects.get(Q(organization_id=organization_id) & Q(leave_applicable_for_id=cuser.center_id) & Q(id=i.id))
                    if center_leave.accrude_monthly:
                        total_leaves = float(center_leave.monthly_leaves) if center_leave.monthly_leaves else 0.0
                    else:
                        total_leaves = float(center_leave.yearly_leaves) if center_leave.yearly_leaves else 0.0

                    used_leaves = 0
                    user_leaves_type = leaveApplication.objects.filter(Q(leave_type_id=i.id) & Q(user_id=user_id) & Q(organization_id=organization_id) & Q(leaveApplication_from_date__lte=end_of_month_timestamp)).values().order_by('-id')
                    for j in user_leaves_type:
                        if j['approved_state'] != 'DECLINED':
                            if j['days']:
                                used_leaves += float(j['days'])

                    leave_balance = float(center_leave.no_of_leaves) - float(used_leaves)

                    leave_balance_dic = {
                        'leave_type': i.leave_title,
                        'leave_type_id': i.id,
                        'leave_allotted': float(center_leave.no_of_leaves),
                        'leaves_used': float(used_leaves),
                        'leave_balance': leave_balance,
                        'added_leaves':total_leaves,
                        'accrude_monthly':center_leave.accrude_monthly
                    }
                    leave_balance_list.append(leave_balance_dic)

                except MasterLeaveTypes.DoesNotExist:
                    print("MasterLeaveTypes.DoesNotExist")

            if pagination == 'FALSE':
                return Response({
                    'result': {
                        'status': 'My leaves by user_id',
                        'leave_balance': {
                            'data': leave_balance_list
                        },
                        'leave_details': {
                            'data': complete_data
                        }
                    }
                })
            else:
                data_pagination = EztimeAppPagination(complete_data, page_number, data_per_page, request)
                data_pagination_l = EztimeAppPagination(leave_balance_list, page_number, data_per_page, request)

                return Response({
                    'result': {
                        'status': 'My leaves by user_id',
                        'leave_balance': {
                            'pagination': {
                                'current_page': data_pagination_l[1]['current_page'],
                                'number_of_pages': data_pagination_l[1]['number_of_pages'],
                                'next_url': data_pagination_l[1]['next_url'],
                                'previous_url': data_pagination_l[1]['previous_url'],
                                'has_next': data_pagination_l[1]['has_next'],
                                'has_previous': data_pagination_l[1]['has_previous'],
                                'has_other_pages': data_pagination_l[1]['has_other_pages'],
                            },
                            'data': data_pagination_l[0]
                        },
                        'leave_details': {
                            'pagination': {
                                'current_page': data_pagination[1]['current_page'],
                                'number_of_pages': data_pagination[1]['number_of_pages'],
                                'next_url': data_pagination[1]['next_url'],
                                'previous_url': data_pagination[1]['previous_url'],
                                'has_next': data_pagination[1]['has_next'],
                                'has_previous': data_pagination[1]['has_previous'],
                                'has_other_pages': data_pagination[1]['has_other_pages'],
                            },
                            'data': data_pagination[0]
                        }
                    }
                })
        else:
            if pagination == 'FALSE':
                all_data = leaveApplication.objects.filter(organization_id=organization_id).values().order_by('-id')
                return Response({
                    'result': {
                        'status': 'GET all without pagination',
                        'data': all_data
                    }
                })

            if id:
                all_data = leaveApplication.objects.filter(Q(id=id) & Q(organization_id=organization_id)).values().order_by('-id')
                data_pagination = EztimeAppPagination(all_data, page_number, data_per_page, request)

                return Response({
                    'result': {
                        'status': 'GET ALL',
                        'pagination': {
                            'current_page': data_pagination[1]['current_page'],
                            'number_of_pages': data_pagination[1]['number_of_pages'],
                            'next_url': data_pagination[1]['next_url'],
                            'previous_url': data_pagination[1]['previous_url'],
                            'has_next': data_pagination[1]['has_next'],
                            'has_previous': data_pagination[1]['has_previous'],
                            'has_other_pages': data_pagination[1]['has_other_pages'],
                        },
                        'data': data_pagination[0]
                    }
                })

            all_data = leaveApplication.objects.filter(organization_id=organization_id).values().order_by('-id')
            data_pagination = EztimeAppPagination(all_data, page_number, data_per_page, request)

            return Response({
                'result': {
                    'status': 'GET ALL',
                    'pagination': {
                        'current_page': data_pagination[1]['current_page'],
                        'number_of_pages': data_pagination[1]['number_of_pages'],
                        'next_url': data_pagination[1]['next_url'],
                        'previous_url': data_pagination[1]['previous_url'],
                        'has_next': data_pagination[1]['has_next'],
                        'has_previous': data_pagination[1]['has_previous'],
                        'has_other_pages': data_pagination[1]['has_other_pages'],
                    },
                    'data': data_pagination[0]
                }
            })

@method_decorator([AutorizationRequired], name='dispatch')
class  leaveApplicationStateChangeApiView(APIView):
    def post(self,request):
        res = CheckPermission(request)
        if res[0] == 2:
            return res[1]

        data = request.data
        approved_state=data['approved_state']
        id=data['id']
        approved_by_id=data['approved_by_id']
        approved_date=data['approved_date']
        if approved_state == 'YET_TO_APPROVED':
            return Response({
                'error':{'message':'Update your status!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        elif approved_state == 'APPROVED':
            res = CheckPermission(request)
            if res[0] == 2:
                return res[1]

            approved_by_date_timestamp = time.mktime(datetime.datetime.strptime(approved_date, "%d/%m/%Y").timetuple())
            leaveApplication.objects.filter(id=id).update(approved_state=approved_state,approved_by_id=approved_by_id,approved_date=approved_by_date_timestamp)

            get_u_by_leave = leaveApplication.objects.get(id=id)
            cuser_data = CustomUser.objects.get(id=get_u_by_leave.user_id)
            master_leave = MasterLeaveTypes.objects.get(Q(id=get_u_by_leave.leave_type_id))

            from_date = datetime.datetime.fromtimestamp(int(float(get_u_by_leave.leaveApplication_from_date)))
            from_date_convert = from_date.strftime("%d/%m/%Y")

            to_date = datetime.datetime.fromtimestamp(int(float(get_u_by_leave.leaveApplication_to_date)))
            to_date_convert = to_date.strftime("%d/%m/%Y")


            message= 'Hi '+ str(cuser_data.u_first_name) +'\n\nYour leave application has been accepted. '+'\n\nLeave type: '+str(master_leave.leave_title) + '\nFrom Date: '+str(from_date_convert) + '\nTo Date: '+str(to_date_convert) + '\nNumber of days: '+str(get_u_by_leave.days) +'\nReason : '+str(get_u_by_leave.reason)+'\nLeave Balance:'+str(get_u_by_leave.balance)+'\nFrom Session:'+str(get_u_by_leave.from_session)+'\nTo Session:'+str(get_u_by_leave.to_session)+'\n\nRegards'+'\n\nNote:This is an auto-generated mail. Please do not reply.'+'\n\nPS: "This e-mail is generated from ekfrazotechnologies.projectace.com"'
            
            print(message,'message=====>')

            subject= 'RE : '+str(cuser_data.u_first_name)+' Your Leave Application has been Accepted.' 
            email = EmailMessage(subject, message, to=[cuser_data.u_email])
            email.send()

            return Response({'result':{'status':'Updated','message':'Leave application approved successfully!'}})
        elif approved_state == 'DECLINED':
            res = CheckPermission(request)
            if res[0] == 2:
                return res[1]

            approved_by_date_timestamp = time.mktime(datetime.datetime.strptime(approved_date, "%d/%m/%Y").timetuple())
            leaveApplication.objects.filter(id=id).update(approved_state=approved_state,approved_by_id=approved_by_id,approved_date=approved_by_date_timestamp)
            return Response({'result':{'status':'Updated','message':'Leave application declined successfully!'}})
        else:
            return Response({
                'error':{'message':'Check your status!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

def CheckLeaveSendEmail(user_id,days,leaveApplication_from_date,leaveApplication_to_date,reason,leave_type_id):
    get_user_data = CustomUser.objects.get(id=user_id)
    user_role_info = UserRole.objects.get(id = get_user_data.user_role_id)
    
    get_user_by_org = CustomUser.objects.filter(organization_id=get_user_data.organization_id).all().values()
    
    for o in get_user_by_org:
        user_role_info_by_org = UserRole.objects.get(id = o['user_role_id'])
        email_sent_to = "NONE"
        if user_role_info.user_role_name == "MANAGER":
            if user_role_info_by_org.user_role_name == "ADMIN":
                email_sent_to = o['u_email']
        
        if user_role_info.user_role_name == "ADMIN":
            if user_role_info_by_org.user_role_name == "SUPER ADMIN":
                email_sent_to = o['u_email']

        if user_role_info_by_org.user_role_name == "MANAGER":
            email_sent_to = o['u_email']

        if email_sent_to != "NONE":
            print(email_sent_to,'email_sent====>')
            
            master_leave = MasterLeaveTypes.objects.get(id=leave_type_id)

            message= 'Hi '+ o['u_first_name']+'\n\nYou recived leave application request from '+str(get_user_data.u_first_name)+'\n\nLeave type: '+str(master_leave.leave_title) + '\nFrom Date: '+str(leaveApplication_from_date) + '\nTo Date: '+str(leaveApplication_to_date) + '\nNumber of days: '+str(days) +'\nReason : '+str(reason)+'\n\nRegards'+'\n\nNote:This is an auto-generated mail. Please do not reply.'+'\n\nPS: "This e-mail is generated from ekfrazotechnologies.projectace.com"'
                        
            print(message,'message=====>')

            subject= 'RE : '+str(get_user_data.u_first_name)+' applied leave in project ACE portal' 
            email = EmailMessage(subject, message, to=[email_sent_to])
            email.send()
        else:
            print(email_sent_to,'email_sent_to==>NONE')
            

    return 1

def CheckLeaveSendEmailTOCC(user_id,days,leaveApplication_from_date,leaveApplication_to_date,reason,leave_type_id,cc_to):
    get_user_data = CustomUser.objects.get(id=user_id)
    
    for o in cc_to:
        if CustomUser.objects.filter(id=o).exists():
            cuser_data = CustomUser.objects.get(id=o)
            email_sent_to = cuser_data.u_email
       
            master_leave = MasterLeaveTypes.objects.get(id=leave_type_id)

            message= 'Hi '+ cuser_data.u_first_name+'\n\nYou recived leave application request from '+str(get_user_data.u_first_name)+'\n\nLeave type: '+str(master_leave.leave_title) + '\nFrom Date: '+str(leaveApplication_from_date) + '\nTo Date: '+str(leaveApplication_to_date) + '\nNumber of days: '+str(days) +'\nReason : '+str(reason)+'\n\nRegards'+'\n\nNote:This is an auto-generated mail. Please do not reply.'+'\n\nPS: "This e-mail is generated from ekfrazotechnologies.projectace.com"'
                        
            print(message,'message=====>')

            subject= 'RE : '+str(get_user_data.u_first_name)+' applied leave in project ACE portal' 
            email = EmailMessage(subject, message, to=[email_sent_to])
            email.send()
        else:
            print(email_sent_to,'email_sent_to==>NONE')
            

    return 1


@method_decorator([csrf_exempt,AutorizationRequired], name='dispatch')
class  leaveApplicationApiView(APIView):
    def get(self,request):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
        print(res,'res=====>')
        id = request.query_params.get('id')
        approved_state = request.query_params.get('approved_state')
        user_id= request.query_params.get('user_id')
        lfd= request.query_params.get('leaveApplication_from_date')
        ltd= request.query_params.get('leaveApplication_to_date')

        key = {'organization_id','page_number','data_per_page','pagination'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = request.query_params.get('organization_id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')

        if pagination == 'FALSE':
            all_data = leaveApplication.objects.filter(organization_id=organization_id).values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(id=id)).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})

        elif approved_state:
            if user_id:
                if lfd:

                    from_date = time.mktime(datetime.datetime.strptime(lfd, "%d/%m/%Y").timetuple())
                    to_date = time.mktime(datetime.datetime.strptime(ltd, "%d/%m/%Y").timetuple())
                    
                    all_data = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(user_id=user_id) & Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date)).values().order_by('-id')
                    
                    final_data = []
                    for k in all_data:
                        # ALLOTED leaves and Used Leaves

                        try:
                            center_leave = MasterLeaveTypes.objects.get(Q(id=k['leave_type_id']))
                        except ObjectDoesNotExist:
                            return Response({
                            'error':{'message':'Record not found!',
                            'status_code':status.HTTP_404_NOT_FOUND,
                            }},status=status.HTTP_404_NOT_FOUND)

                        total_leaves = 0.0
                        if center_leave.accrude_monthly == True:
                            if center_leave.monthly_leaves:
                                total_leaves = float(center_leave.no_of_leaves)
                                leave_type = 'monthly_leaves'
                        elif center_leave.accrude_monthly == False:
                            if center_leave.yearly_leaves:
                                total_leaves =  float(center_leave.no_of_leaves)
                                leave_type = 'yearly_leaves'
                        else:
                            return Response({
                                'error':{'message':'Master leave type should have accrude_monthly flag',
                                'hint':'Check the Master leave',
                                'status_code':status.HTTP_400_BAD_REQUEST,
                                }},status=status.HTTP_400_BAD_REQUEST)
                        used_leaves = float(total_leaves) - float(k['balance'])

                        from_date = k['c_timestamp'].strftime("%d/%m/%Y") if k['c_timestamp'] else ''
                        updated_date = k['m_timestamp'].strftime("%d/%m/%Y") if k['m_timestamp'] else ''
                        
                       
                        you_applied_leave_from_date = datetime.datetime.fromtimestamp(float(k['leaveApplication_from_date'])).strftime("%d/%m/%Y")
                        you_applied_leave_to_date = datetime.datetime.fromtimestamp(float(k['leaveApplication_to_date'])).strftime("%d/%m/%Y")
                        
                        user_data = CustomUser.objects.get(id = k['user_id'])
                        
                        final_dic = {
                            'id':k['id'],
                            'leave_type_id':k['leave_type_id'],
                            'user_id':k['user_id'],
                            'people_first_name':user_data.u_first_name,
                            'people_last_name':user_data.u_last_name,
                            'people_email':user_data.u_email,
                            'reason':k['reason'],
                            'contact_details':k['contact_details'],
                            'leave_application_file_path':k['leave_application_file_path'],
                            'cc_to':k['cc_to'],
                            'leaveApplication_from_date_time_stamp':k['leaveApplication_from_date'],
                            'leaveApplication_to_date_time_stamp':k['leaveApplication_to_date'],
                            'your_applied_leave_from_date':you_applied_leave_from_date,
                            'your_applied_leave_to_date':you_applied_leave_to_date,
                            # 'leaveApplication_from_date':lfd,
                            # 'leaveApplication_to_date':ltd,
                            'applied_days':k['days'],
                            'from_session':k['from_session'],
                            'to_session':k['to_session'],
                            'leave_balance':k['balance'],
                            'applied_date_timestamp':k['c_timestamp'],
                            'modified_date_timestamp':k['m_timestamp'],
                            'applied_date':from_date,
                            'modified_date':updated_date,
                            'status':k['approved_state'],
                            'used_leaves':used_leaves,
                            'leave_type':leave_type,
                            'alloted_leaves':total_leaves,
                            'approved_by_id':k['approved_by_id'],
                            'request':k['request'],

                        }
                        if k['approved_date']:
                            
                            approved_date =datetime.datetime.fromtimestamp(int(float(k['approved_date']))).strftime('%d/%m/%Y')
                            approved_user_object = CustomUser.objects.get(id=k['approved_by_id'])
                            final_dic['approved_date']=approved_date
                            final_dic['approved_by_name']=approved_user_object.u_first_name
                            final_dic['approved_by_email']=approved_user_object.u_email

                        else:
                            final_dic['approved_date']=None
                            final_dic['approved_by_name']=None
                            final_dic['approved_by_email']=None


                        final_data.append(final_dic)

                    from_date = time.mktime(datetime.datetime.strptime(lfd, "%d/%m/%Y").timetuple())
                    to_date = time.mktime(datetime.datetime.strptime(ltd, "%d/%m/%Y").timetuple())

                    
                    yet_to_be_approved_count = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED') & Q(user_id=user_id) & Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date)).count()

                    approved_count = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED') & Q(user_id=user_id) & Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date)).count()

                    declined_count = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED') & Q(user_id=user_id) & Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date)).count()

                    all_count = {
                        'request_count':yet_to_be_approved_count,
                        'approved_count':approved_count,
                        'declined_count':declined_count,
                    }

                    data_pagination = EztimeAppPagination(final_data,page_number,data_per_page,request)

                    return Response({'result':{'status':'Get by ApprovedState and user_id','leave_dashboard':all_count,
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

                    all_data = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state) & Q(user_id=user_id)).values().order_by('-id')

                    final_data = []
                    for k in all_data:
                        # ALLOTED leaves and Used Leaves

                        try:
                            center_leave = MasterLeaveTypes.objects.get( Q(id=k['leave_type_id']))
                        except ObjectDoesNotExist:
                            return Response({
                            'error':{'message':'Record not found!',
                            'status_code':status.HTTP_404_NOT_FOUND,
                            }},status=status.HTTP_404_NOT_FOUND)

                        total_leaves = 0
                        if center_leave.accrude_monthly == True:
                            total_leaves = float(center_leave.no_of_leaves)
                            leave_type = 'monthly_leaves'
                        elif center_leave.accrude_monthly == False:
                            total_leaves =  float(center_leave.no_of_leaves)
                            leave_type = 'yearly_leaves'
                        else:
                            return Response({
                                'error':{'message':'Master leave type should have accrude_monthly flag',
                                'hint':'Check the Master leave',
                                'status_code':status.HTTP_400_BAD_REQUEST,
                                }},status=status.HTTP_400_BAD_REQUEST)


                        used_leaves =  float(total_leaves) - float(k['balance'])
                       
                        from_date = k['c_timestamp'].strftime("%d/%m/%Y")
                        updated_date = k['m_timestamp'].strftime("%d/%m/%Y")
                        
                        user_data = CustomUser.objects.get(id = k['user_id'])

                        you_applied_leave_from_date = datetime.datetime.fromtimestamp(float(k['leaveApplication_from_date'])).strftime("%d/%m/%Y")
                        you_applied_leave_to_date = datetime.datetime.fromtimestamp(float(k['leaveApplication_to_date'])).strftime("%d/%m/%Y")
                        
                        
                        final_dic = {
                            'id':k['id'],
                            'leave_type_id':k['leave_type_id'],
                            'user_id':k['user_id'],
                            'people_first_name':user_data.u_first_name,
                            'people_last_name':user_data.u_last_name,
                            'people_email':user_data.u_email,
                            'reason':k['reason'],
                            'contact_details':k['contact_details'],
                            'leave_application_file_path':k['leave_application_file_path'],
                            'cc_to':k['cc_to'],
                            'leaveApplication_from_date_time_stamp':k['leaveApplication_from_date'],
                            'leaveApplication_to_date_time_stamp':k['leaveApplication_to_date'],
                            'your_applied_leave_from_date':you_applied_leave_from_date,
                            'your_applied_leave_to_date':you_applied_leave_to_date,
                            # 'leaveApplication_from_date':lfd,
                            # 'leaveApplication_to_date':ltd,
                            'applied_days':k['days'],
                            'from_session':k['from_session'],
                            'to_session':k['to_session'],
                            'leave_balance':k['balance'],
                            'applied_date_timestamp':k['c_timestamp'],
                            'modified_date_timestamp':k['m_timestamp'],
                            'applied_date':from_date,
                            'modified_date':updated_date,
                            'status':k['approved_state'],
                            'used_leaves':used_leaves,
                            'leave_type':leave_type,
                            'alloted_leaves':total_leaves,
                            'approved_by_id':k['approved_by_id'],
                            'request':k['request'],
                        }
                        if k['approved_date']:
                            
                            approved_date =datetime.datetime.fromtimestamp(int(float(k['approved_date']))).strftime('%d/%m/%Y')
                            approved_user_object = CustomUser.objects.get(id=k['approved_by_id'])
                            final_dic['approved_date']=approved_date
                            final_dic['approved_by_name']=approved_user_object.u_first_name
                            final_dic['approved_by_email']=approved_user_object.u_email

                        else:
                            final_dic['approved_date']=None
                            final_dic['approved_by_name']=None
                            final_dic['approved_by_email']=None


                        final_data.append(final_dic)


                    yet_to_be_approved_count = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state='YET_TO_APPROVED') & Q(user_id=user_id)).count()
                    approved_count = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state='APPROVED') & Q(user_id=user_id)).count()
                    declined_count = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state='DECLINED') & Q(user_id=user_id) ).count()
                    
                    all_count = {
                        'request_count':yet_to_be_approved_count,
                        'approved_count':approved_count,
                        'declined_count':declined_count,
                    }

                    data_pagination = EztimeAppPagination(final_data,page_number,data_per_page,request)

                    return Response({'result':{'status':'Get by ApprovedState and user_id','leave_dashboard':all_count,
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
                all_data = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(approved_state=approved_state)).values().order_by('-id')

                final_data = []
                for k in all_data:
                    # ALLOTED leaves and Used Leaves

                    try:
                        center_leave = MasterLeaveTypes.objects.get(Q(id=k['leave_type_id']))
                    except ObjectDoesNotExist:
                        return Response({
                        'error':{'message':'Record not found!',
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)

                    total_leaves = 0
                    if center_leave.accrude_monthly == True:
                        total_leaves = float(center_leave.no_of_leaves)
                        leave_type = 'monthly_leaves'
                    elif center_leave.accrude_monthly == False:
                        total_leaves = float(center_leave.no_of_leaves) 
                        leave_type = 'yearly_leaves'
                    else:
                        return Response({
                            'error':{'message':'Master leave type should have accrude_monthly flag',
                            'hint':'Check the Master leave',
                            'status_code':status.HTTP_400_BAD_REQUEST,
                            }},status=status.HTTP_400_BAD_REQUEST)
                    used_leaves =  float(total_leaves) - float(k['balance'])
                    
                    from_date = k['c_timestamp'].strftime("%d/%m/%Y")
                    updated_date = k['m_timestamp'].strftime("%d/%m/%Y")
                    
                    user_data = CustomUser.objects.get(id = k['user_id'])
                    
                    you_applied_leave_from_date = datetime.datetime.fromtimestamp(float(k['leaveApplication_from_date'])).strftime("%d/%m/%Y")
                    you_applied_leave_to_date = datetime.datetime.fromtimestamp(float(k['leaveApplication_to_date'])).strftime("%d/%m/%Y")
                        
                    final_dic = {
                        'id':k['id'],
                        'leave_type_id':k['leave_type_id'],
                        'user_id':k['user_id'],
                        'people_first_name':user_data.u_first_name,
                        'people_last_name':user_data.u_last_name,
                        'people_email':user_data.u_email,
                        'reason':k['reason'],
                        'contact_details':k['contact_details'],
                        'leave_application_file_path':k['leave_application_file_path'],
                        'cc_to':k['cc_to'],
                        'leaveApplication_from_date_time_stamp':k['leaveApplication_from_date'],
                        'leaveApplication_to_date_time_stamp':k['leaveApplication_to_date'],
                        'your_applied_leave_from_date':you_applied_leave_from_date,
                        'your_applied_leave_to_date':you_applied_leave_to_date,
                        # 'leaveApplication_from_date':lfd,
                        # 'leaveApplication_to_date':ltd,
                        'applied_days':k['days'],
                        'from_session':k['from_session'],
                        'to_session':k['to_session'],
                        'leave_balance':k['balance'],
                        'applied_date_timestamp':k['c_timestamp'],
                        'modified_date_timestamp':k['m_timestamp'],
                        'applied_date':from_date,
                        'modified_date':updated_date,
                        'status':k['approved_state'],
                        'used_leaves':used_leaves,
                        'leave_type':leave_type,
                        'alloted_leaves':total_leaves,
                        'approved_by_id':k['approved_by_id'],
                        'request':k['request'],
                    }
                    if k['approved_date']:
                        
                        approved_date =datetime.datetime.fromtimestamp(int(float(k['approved_date']))).strftime('%d/%m/%Y')
                        approved_user_object = CustomUser.objects.get(id=k['approved_by_id'])
                        final_dic['approved_date']=approved_date
                        final_dic['approved_by_name']=approved_user_object.u_first_name
                        final_dic['approved_by_email']=approved_user_object.u_email

                    else:
                        final_dic['approved_date']=None
                        final_dic['approved_by_name']=None
                        final_dic['approved_by_email']=None


                    final_data.append(final_dic)



                data_pagination = EztimeAppPagination(final_data,page_number,data_per_page,request)

                return Response({'result':{'status':'Get by ApprovedState',
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

            all_data = leaveApplication.objects.filter(Q(organization_id=organization_id)).values().order_by('-id')
            data_pagination = EztimeAppPagination(all_data,page_number,data_per_page,request)

            return Response({'result':{'status':'GET_ALL',
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
                

            

    def post(self,request):
        data = request.data
        res = CheckPermission(request)
        if res[0] == 2:
            return res[1]

        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        organization_id=data['organization_id']

        print(res,'res=====>')
        leave_type=data['leave_type_id']
        user_id = data['user_id']
        reason=data['reason']
        contact_details=data['contact_details']
        
        cc_to=data['cc_to']
        lfd=data['leaveApplication_from_date']
        ltd=data['leaveApplication_to_date']
        days=data['days']
        from_session=data['from_session']
        to_session=data['to_session']
        balance=data['balance']

        leaveApplication_from_date = time.mktime(datetime.datetime.strptime(lfd, "%d/%m/%Y").timetuple())
        print(leaveApplication_from_date,'stamppppppppppppppp')

        leaveApplication_to_date = time.mktime(datetime.datetime.strptime(ltd, "%d/%m/%Y").timetuple())
        print(leaveApplication_to_date,'stamppppppppppppppp')
        
        # ======= Parse the lfd to get a datetime object
        parsed_date = datetime.datetime.strptime(lfd, "%d/%m/%Y")
        parsed_date_to = datetime.datetime.strptime(ltd, "%d/%m/%Y")

        # Get the first day of the month
        start_of_month_date = datetime.date(parsed_date.year, parsed_date.month, 1)
        start_of_month_timestamp = time.mktime(datetime.datetime.combine(start_of_month_date, datetime.datetime.min.time()).timetuple())

        # Get the last day of the month
        last_day = calendar.monthrange(parsed_date.year, parsed_date.month)[1]
        end_of_month_date = datetime.date(parsed_date.year, parsed_date.month, last_day)
        end_of_month_timestamp = time.mktime(datetime.datetime.combine(end_of_month_date, datetime.datetime.min.time()).timetuple())

        print("Start of the month date:", start_of_month_date)
        print("Start of the month timestamp:", start_of_month_timestamp)
        print("End of the month date:", end_of_month_date)
        print("End of the month timestamp:", end_of_month_timestamp)


    
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)


        # other months ===================
        cuser = CustomUser.objects.get(id=user_id)
        center_leave = MasterLeaveTypes.objects.get(Q(leave_applicable_for_id=cuser.center_id) & Q(id=leave_type))
        if center_leave.accrude_monthly == True:
            if parsed_date.month != parsed_date_to.month:
                return Response({
                    'error': {
                        'message': 'You do not allowed to apply leave of combine multiple month leave at once' ,
                        'info':'Leave type is accrude monthly, we cannot combine multiple month leave at once',
                        'status_code': status.HTTP_404_NOT_FOUND,
                    }
                }, status=status.HTTP_404_NOT_FOUND)


        if leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(user_id=user_id)& ~Q(approved_state="DECLINED") ).exists():
            leave_data = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(user_id=user_id)& ~Q(approved_state="DECLINED") & Q(leaveApplication_from_date__gte=start_of_month_timestamp) & Q(leaveApplication_to_date__lte=end_of_month_timestamp))
            
            print(leave_data,'leave_type===>123')
            for k in leave_data:
                
                if center_leave.accrude_monthly == True:
                    monthly_leaves = center_leave.monthly_leaves
                    no_of_leaves = center_leave.no_of_leaves
                else:
                    yearly_leaves = center_leave.yearly_leaves
                    no_of_leaves = center_leave.no_of_leaves
                    
                total_leaves_taken = 0
                all_data = leaveApplication.objects.filter(Q(leave_type_id=leave_type) & Q(user_id=user_id) & Q(leaveApplication_from_date__gte=start_of_month_timestamp) & Q(leaveApplication_to_date__lte=end_of_month_timestamp)).values().order_by('-id')
                print(all_data,'all_data===>')
                for t in all_data:
                    if t['approved_state'] != 'DECLINED':
                        total_leaves_taken = total_leaves_taken + float(t['days'])

                total_leaves_left = float(no_of_leaves) - float(total_leaves_taken)
                print(total_leaves_left,'total_leaves_left===>')
                if total_leaves_left <= 0.0:
                    return Response({
                    'error': {
                        'message': 'You do not have enough leaves left to apply this month',
                        'total_leaves_you_have': float(no_of_leaves),
                        'total_leaves_taken': float(total_leaves_taken),
                        'total_leaves_left': float(total_leaves_left),
                        'insternal':'1',
                        'status_code': status.HTTP_404_NOT_FOUND,
                    }
                }, status=status.HTTP_404_NOT_FOUND)
                
                
        # =================================================================

        if leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(user_id=user_id)& ~Q(approved_state="DECLINED")).exists():

            leave_data = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(user_id=user_id)& ~Q(approved_state="DECLINED"))

            for k in leave_data:

                print(leaveApplication_from_date,'leaveApplication_from_date===',k.leaveApplication_from_date,'k.leaveApplication_from_date===')

                if float(leaveApplication_from_date) == float(k.leaveApplication_from_date):

                    
                    if (k.from_session == from_session ) | (k.to_session == to_session):
                        return Response({
                            'error':{'message':'You already applied for leave on this day on this session',
                            'hint':'check my leave section to know abount you current leave dates',
                            'description':'Check all date you applied leaves',
                            'status_code':status.HTTP_400_BAD_REQUEST,
                            }},status=status.HTTP_400_BAD_REQUEST)

                    print("Both are same ")
                    countdays2 = float(k.days)
                    result2 = int(countdays2) / 0.5
                    if int(result2) != 0 and int(result2) % 2 == 0:
                        print(int(result2) % 2,'modulusss',int(countdays2),'int(countdays2)',result2,'result2')
                        return Response({
                                'error':{'message':'You already applied for leave on this day',
                                'hint':'check my leave section to know abount you current leave dates - 1 ',
                                'description':'Check all date you applied leaves',
                                'status_code':status.HTTP_400_BAD_REQUEST,
                                }},status=status.HTTP_400_BAD_REQUEST)

                if (float(leaveApplication_from_date) >= float(k.leaveApplication_from_date)) | (float(leaveApplication_from_date) <= float(k.leaveApplication_from_date)):
                    print("150 > 100 DB",k.id)
                    if float(leaveApplication_from_date) >= float(k.leaveApplication_to_date):
                        print("150 < 200 DB",leaveApplication_from_date,'leaveApplication_from_date==1',k.leaveApplication_to_date,'k.leaveApplication_to_date==>2')
                        
                        countdays = float(k.days)
                        result = int(countdays) / 0.5
                        print(int(result),'result==>123')
                        if int(result) != 0 and int(result) % 2 == 0:
                            return Response({
                                'error':{'message':'You already applied for leave on this day',
                                'hint':'check my leave section to know abount you current leave dates - 2',
                                'description':'Check all date you applied leaves',
                                'status_code':status.HTTP_400_BAD_REQUEST,
                                }},status=status.HTTP_400_BAD_REQUEST)
                
                    else:
                        print("250 > 200 DB",k.id)
                        
                # if float(leaveApplication_from_date) <= float(k.leaveApplication_from_date):
                    
                #     print("150 < 200 DB",k.id)
                #     if float(leaveApplication_to_date) <= float(k.leaveApplication_from_date):
                #         print("150 < 200 DB",k.id)
                #     else:
                #         countdays2 = float(k.days)
                #         if countdays2 % 0.5 == 0:
                #             result1 = int(countdays2) / 0.5
                #             print(int(result1),'result==>123==1')
                #             if int(result1) % 2 == 0:
                #                 return Response({
                #                 'error':{'message':'You already applied for leave on this day',
                #                 'hint':'check my leave section to know abount you current leave - 1',
                #                 'status_code':status.HTTP_400_BAD_REQUEST,
                #                 }},status=status.HTTP_400_BAD_REQUEST)


        try:
            file_stored_path = '/eztime/django/site/media/leave_files/'
            project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
            leave_application_file_attachment=data.get('leave_application_file_attachment')

            if leave_application_file_attachment != '':
                stored_path = StoreBase64ReturnPath(leave_application_file_attachment, file_stored_path, project_base_url)
                
                leaveApplication.objects.create(
                    organization_id=organization_id,
                    leave_type_id=leave_type,
                    user_id=user_id,
                    reason=reason,
                    contact_details=contact_details,
                    leave_application_file_path=stored_path,
                    cc_to=cc_to,
                    leaveApplication_from_date=leaveApplication_from_date,
                    leaveApplication_to_date=leaveApplication_to_date,
                    days=days,
                    from_session=from_session,
                    to_session=to_session,
                    balance=balance,
                    approved_state='YET_TO_APPROVED'
                    )
                CheckLeaveSendEmail(user_id,days,lfd,ltd,reason,leave_type)
                if len(cc_to) > 0:
                    CheckLeaveSendEmailTOCC(user_id,days,lfd,ltd,reason,leave_type,cc_to)

            else:

                leaveApplication.objects.create(
                    organization_id=organization_id,
                    leave_type_id=leave_type,
                    user_id=user_id,
                    reason=reason,
                    contact_details=contact_details,
                    cc_to=cc_to,
                    leaveApplication_from_date=leaveApplication_from_date,
                    leaveApplication_to_date=leaveApplication_to_date,
                    days=days,
                    from_session=from_session,
                    to_session=to_session,
                    balance=balance,
                    approved_state='YET_TO_APPROVED'
                    )
                CheckLeaveSendEmail(user_id,days,lfd,ltd,reason,leave_type)
                if len(cc_to) > 0:
                    CheckLeaveSendEmailTOCC(user_id,days,lfd,ltd,reason,leave_type,cc_to)

            posts = leaveApplication.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        res = CheckPermission(request)
        if res[0] == 2:
            return res[1]

        leave_type=data['leave_type_id']
        user_id=data['user_id']
        reason=data['reason']
        contact_details=data['contact_details']
        
        cc_to=data['cc_to']
        lfd=data['leaveApplication_from_date']
        ltd=data['leaveApplication_to_date']
        days=data['days']
        from_session=data['from_session']
        to_session=data['to_session']
        balance=data['balance']

        leaveApplication_from_date = time.mktime(datetime.datetime.strptime(lfd, "%d/%m/%Y").timetuple())
        print(leaveApplication_from_date,'stamppppppppppppppp')

        leaveApplication_to_date = time.mktime(datetime.datetime.strptime(ltd, "%d/%m/%Y").timetuple())
        print(leaveApplication_to_date,'stamppppppppppppppp')
        
    

        
        try:
            file_stored_path = '/eztime/django/site/media/leave_files/'
            project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
            leave_application_file_attachment=data.get('leave_application_file_attachment')

            if leave_application_file_attachment != '':
                stored_path = StoreBase64ReturnPath(leave_application_file_attachment, file_stored_path, project_base_url)

                leaveApplication.objects.filter(id=pk).update(leave_type_id=leave_type,
                user_id=user_id,
                                                reason=reason,
                                                contact_details=contact_details,
                                                leave_application_file_path=stored_path,
                                                cc_to=cc_to,
                                                leaveApplication_from_date=leaveApplication_from_date,
                                                leaveApplication_to_date=leaveApplication_to_date,
                                                days=days,
                                                from_session=from_session,
                                                to_session=to_session,
                                                balance=balance,
                                            )


            else:

                leaveApplication.objects.create(leave_type_id=leave_type,
                user_id=user_id,
                                                reason=reason,
                                                contact_details=contact_details,
                                                cc_to=cc_to,
                                                leaveApplication_from_date=leaveApplication_from_date,
                                                leaveApplication_to_date=leaveApplication_to_date,
                                                days=days,
                                                from_session=from_session,
                                                to_session=to_session,
                                                balance=balance,)
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]

        test = (0,{})
            
        all_values = leaveApplication.objects.filter(id=pk).delete()
        if test == all_values:

            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})

@method_decorator([AutorizationRequired], name='dispatch')
class  ProfileApiView(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = Profile.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            all_data = Profile.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            return Response({'result':{'status':'GET by Id','data':all_data}})
        else:
            all_data = Profile.objects.all().values().order_by('-id')
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




    def post(self,request):
        data = request.data
        first_name=data.get('first_name')
        last_name=data.get('last_name')
        designation=data.get('designation')
        email_id=data.get('email_id')
        user_address_details=data.get('user_address_details')
        country=data.get('country')
        state=data.get('state')
        city=data.get('city')
        address=data.get('address')
        phone_number=data.get('phone_number')
        dob=data.get('dob')
        tags=data.get('tags')
        postal_code=data.get('postal_code')
        # user_profile_photo=request.FILES['user_profile_photo']
        date_of_birth = time.mktime(datetime.datetime.strptime(dob, "%d/%m/%Y").timetuple())
        user_profile_photo = data['user_profile_photo']
        base64_data =user_profile_photo
        split_base_url_data=user_profile_photo.split(';base64,')[1]
        imgdata1 = base64.b64decode(split_base_url_data)
        data_split = user_profile_photo.split(';base64,')[0]
        extension_data = re.split(':|;', data_split)[1] 
        guess_extension_data = guess_extension(extension_data)
        # print(guess_extension_data,'guess_extension_data')
        filename1 = "/eztime/django/site/media/user_profile_photo/"+first_name+guess_extension_data
        # filename1 = "D:/EzTime/eztimeproject/media/photo/"+name+'.png'
        fname1 = '/user_profile_photo/'+first_name+guess_extension_data
        ss=  open(filename1, 'wb')
        print(ss)
        ss.write(imgdata1)
        ss.close()   
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        try:
            profile_data = Profile.objects.create(first_name=first_name,
                last_name=last_name,
                designation=designation,
                email_id=email_id,
                user_address_details=user_address_details,
                country=country,
                state=state,
                city=city,
                address=address,
                phone_number=phone_number,
                dob=date_of_birth,
                tags=tags,
                postal_code=postal_code,
                base64=base64_data,
                user_profile_photo=fname1,
                )
            if user_profile_photo:
                # profile_data.photo_path = 'http://127.0.0.1:8000/media/user_profile_photo/'+ (str(profile_data.user_profile_photo)).split('user_profile_photo/')[1]
                profile_data.photo_path = 'https://projectaceuat.thestorywallcafe.com/media/user_profile_photo/'+ (str(profile_data.user_profile_photo)).split('user_profile_photo/')[1]
                profile_data.save()
            posts = Profile.objects.all().values().order_by('-id')
            paginator = Paginator(posts,10)
            try:
                page_obj = paginator.get_page(selected_page_no)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)
            return Response({'result':{'status':'Created','data':list(page_obj)}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,pk):
        data = request.data
        first_name=data.get('first_name')
        last_name=data.get('last_name')
        designation=data.get('designation')
        email_id=data.get('email_id')
        user_address_details=data.get('user_address_details')
        country=data.get('country')
        state=data.get('state')
        city=data.get('city')
        address=data.get('address')
        phone_number=data.get('phone_number')
        dob=data.get('dob')
        tags=data.get('tags')
        postal_code=data.get('postal_code')
        # user_profile_photo=request.FILES['user_profile_photo']
        date_of_birth = time.mktime(datetime.datetime.strptime(dob, "%d/%m/%Y").timetuple())
        user_profile_photo = data['user_profile_photo']
        print(user_profile_photo,'Attttttttttttttttttttt')
        if user_profile_photo == '':
            print('in if nulll looopp')
            try:
                Profile.objects.filter(id=pk).update(
                    first_name=first_name,
                    last_name=last_name,
                    designation=designation,
                    email_id=email_id,
                    user_address_details=user_address_details,
                    country=country,
                    state=state,
                    city=city,
                    address=address,
                    phone_number=phone_number,
                    tags=tags,
                    postal_code=postal_code,
                    dob=date_of_birth,
                    # base64 =base64_data,
                    # user_profile_photo=fname1,
                                        )
                return Response({'result':{'status':'Updated'}})
            except IntegrityError as e:
                error_message = e.args
                return Response({
                'error':{'message':'DB error!',
                'detail':error_message,
                'status_code':status.HTTP_400_BAD_REQUEST,
                }},status=status.HTTP_400_BAD_REQUEST)
                
        base64_data =user_profile_photo
        split_base_url_data=user_profile_photo.split(';base64,')[1]
        imgdata1 = base64.b64decode(split_base_url_data)
        
        data_split = user_profile_photo.split(';base64,')[0]
        extension_data = re.split(':|;', data_split)[1] 
        guess_extension_data = guess_extension(extension_data)

        filename1 = "/eztime/django/site/media/user_profile_photo/"+first_name+guess_extension_data
        # filename1 = "D:/EzTime/eztimeproject/media/photo/"+name+'.png'
        fname1 = '/user_profile_photo/'+first_name+guess_extension_data
        ss=  open(filename1, 'wb')
        print(ss)
        ss.write(imgdata1)
        ss.close()  
        try:
            Profile.objects.filter(id=pk).update(first_name=first_name,
                last_name=last_name,
                designation=designation,
                email_id=email_id,
                user_address_details=user_address_details,
                country=country,
                state=state,
                city=city,
                address=address,
                phone_number=phone_number,
                tags=tags,
                postal_code=postal_code,
                dob=date_of_birth,
                base64 =base64_data,
                user_profile_photo=fname1,             )
            profile_data = Profile.objects.get(id=pk)
            if user_profile_photo:
                # profile_data.photo_path = 'http://127.0.0.1:8000/media/user_profile_photo/'+ (str(profile_data.user_profile_photo)).split('user_profile_photo/')[1]
                profile_data.photo_path = 'https://projectaceuat.thestorywallcafe.com/media/user_profile_photo/'+ (str(profile_data.user_profile_photo)).split('user_profile_photo/')[1]
                profile_data.save()
            return Response({'result':{'status':'Updated'}})
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)
            

    def delete(self,request,pk):
        test = (0,{})  
        all_values = Profile.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class DashBoardview(APIView):
    def post(self,request):
        data = request.data
        print(request.headers,'request====>tokencheck==header==check')
        all_keys = {'user_id','organization_id'}
        if all_keys <= data.keys():
            user_id = data['user_id']
            organization_id = data['organization_id']
            if user_id:
                cuser_data = CustomUser.objects.get(id=user_id)
                roles = UserRole.objects.get(id=cuser_data.user_role_id)
                dic ={}
                if roles.user_role_name == 'SUPER ADMIN':
                    organization_count = Organization.objects.filter().count()
                    dic['no_of_organization'] = organization_count
                
                    c_user_all_data = CustomUser.objects.filter()
                    for k in c_user_all_data:
                        role_data = UserRole.objects.get(id=k.user_role_id)
                        if (role_data.user_role_name).upper() == 'ADMIN':
                            cuser_data_count = CustomUser.objects.filter(Q(user_role_id=roles.id)).count()
                            dic['no_of_admin'] = cuser_data_count
                        
                    cuser_data_user = CustomUser.objects.filter().count()
                    dic['no_of_users'] = cuser_data_user
                
                roles = UserRole.objects.filter(Q(organization_id=organization_id)).count()
                industry = TypeOfIndustries.objects.filter(Q(org_ref_id=organization_id)).count()
                department = OrganizationDepartment.objects.filter(Q(org_ref_id=organization_id)).count()
                dic['no_of_roles'] = roles
                dic['no_of_industries'] = industry
                dic['no_of_department'] = department

                return Response({'result':dic})
            else:
                return Response({
                    'error':{'message':'user id value not found!',
                    'status_code':status.HTTP_404_NOT_FOUND,}},status=status.HTTP_404_NOT_FOUND)

        
        else:
            missing_keys = all_keys - data.keys()
            return  Response({
                'error':{'message':'Key missing!',
                'description':str(missing_keys) + " key is mandatory",
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        
@method_decorator([AutorizationRequired], name='dispatch')
class SubscriptionPlanAPIView(APIView):
    def get(self,request):
        id = request.query_params.get('id')

        if id:
            try:
                sub_data = SubscriptionPlan.objects.filter(id=id).values().order_by('-id')
                return Response({'result':'Get_by_id','status':'HTTP_200_OK','data':sub_data})
            except SubscriptionPlan.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,}},status=status.HTTP_404_NOT_FOUND)
        else:
            all_data = SubscriptionPlan.objects.all().values().order_by('-id')

            return Response({'result':{'status':'GET ALL',
                'data':all_data
                }})
        

    def post(self,request):
        data = request.data
        plan = data.get('plan')
        type = data.get('type')
        no_of_subscribers = data.get('no_of_subscribers')
        amt_per_user = data.get('amt_per_user')
        total_amount = data.get('total_amount')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        selected_page_no =1 
        page_number = request.GET.get('page')
        if page_number:
            selected_page_no = int(page_number)
        subscription=SubscriptionPlan.objects.create(
                                    plan = plan,
                                    type = type,
                                    no_of_subscribers = no_of_subscribers,
                                    amt_per_user = amt_per_user,
                                    total_amount = total_amount,
                                    start_date = start_date,
                                    end_date = end_date,
                                    )
        response_result = {
                    'result':{'data':'Data added sucessfully',
                    'form_id':subscription.id,
                    'status':'HTTP_200_OK'
                    }}
        return Response(response_result,status= status.HTTP_201_CREATED)



    def put(self,request):
        data = request.data
        id = data.get('id')

        if id:
            data = SubscriptionPlan.objects.filter(id=id).update(
                            plan = data.get('plan'),
                            type = data.get('type'),
                            no_of_subscribers = data.get('no_of_subscribers'),
                            amt_per_user = data.get('amt_per_user'),
                            total_amount = data.get('total_amount'),
                            start_date = data.get('start_date'),
                            end_date = data.get('end_date')
            )
            if data:
                    return JsonResponse({'message': 'data Updated Sucessfully.'})
            else:
                response={'message':"Invalid id"}
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        else:
            return JsonResponse({'message': 'Id. Required'},status=status.HTTP_400_BAD_REQUEST)
        
    def delete(self,request):
        id=self.request.query_params.get('id')
        subscription = SubscriptionPlan.objects.filter(id=id)
        if len(subscription) > 0:
            subscription.delete()
            return Response({'message':'data Deleted Sucessfully'})
        else:
            return Response({'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

@method_decorator([AutorizationRequired], name='dispatch')
class UserRoleApiView(APIView):
    def get(self,request):

        key = {'organization_id','page_number','data_per_page','pagination'}

        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response

        id = request.query_params.get('id')
        user_id = request.query_params.get('user_id')
        organization_id = request.query_params.get('organization_id')
        manager = request.query_params.get('manager')

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        pagination = request.query_params.get('pagination')
        
        if id:
            try:
                user_data = UserRole.objects.filter(Q(id=id) & Q(organization_id=organization_id)).values().order_by('-id')
                return Response({'result':'Get_by_id','status':'HTTP_200_OK','data':user_data})
            except UserRole.DoesNotExist:
                return Response({
                'error':{'message':'Id does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,}},status=status.HTTP_404_NOT_FOUND)
        elif user_id:
            try:
                c_user_data = CustomUser.objects.get(id=user_id)
                user_data = UserRole.objects.filter(Q(id=c_user_data.user_role_id) & Q(organization_id=organization_id)).values().order_by('-id')
                return Response({'result':'Get_by_user_id','status':'HTTP_200_OK','data':user_data})
            except UserRole.DoesNotExist:
                return Response({
                'error':{'message':'User_id related role does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,}},status=status.HTTP_404_NOT_FOUND)
        
        elif manager:
            try:
                final_list = []
                c_user_data = CustomUser.objects.filter(organization_id=organization_id)
                for i in c_user_data:
                    user_data = UserRole.objects.get(Q(id=i.user_role_id))
                    if (user_data.user_role_name).upper() == "MANAGER":
                        dic = {
                            'user_role_name':user_data.user_role_name,
                            'u_first_name':i.u_first_name,
                            'u_last_name':i.u_last_name,
                            'u_email':i.u_email,
                            'u_phone_no':i.u_phone_no,
                        }
                        final_list.append(dic)
                if pagination == 'FALSE':
                    return Response({'result':'Get all without pagination','status':'HTTP_200_OK','data':final_list})
                else:
                    data_pagination = EztimeAppPagination(final_list,page_number,data_per_page,request)
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
            except UserRole.DoesNotExist:
                return Response({
                'error':{'message':'User_id related role does not exists!',
                'status_code':status.HTTP_404_NOT_FOUND,}},status=status.HTTP_404_NOT_FOUND)
        
        
        else:
            if pagination == 'FALSE':
                all_data = UserRole.objects.filter(organization_id=organization_id).values().order_by('-id')
                return Response({'result':{'status':'GET all without pagination','data':all_data}})

            if 'search_key' in request.query_params:
                search_key = request.query_params.get('search_key')
               
                all_data = UserRole.objects.filter(Q(organization_id=organization_id) & (Q(user_role_name__icontains  = search_key)|Q(description__icontains  = search_key)|Q(role_status__icontains  = search_key)|Q(created_time__icontains  = search_key))).values().order_by('-id')
            else:
                all_data = UserRole.objects.filter(organization_id=organization_id).values().order_by('-id')


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


            # return Response({'result':{'status':'GET ALL',
            #     'data':all_data
            #     }})


        # return Response({'result':{'status':'GET','data':all_data}})
    def post(self, request):
        data = request.data
        res = CheckInput(request, 'POST')
        if res[0] == 2:
            return res[1]
        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = data['organization_id']
        user_role_name = data['user_role_name']
        module_name = data['module_name']
        permissions = data['permissions']
        description = data['description']
        priority = data['priority']
        role_status = data['role_status']
        
        # Check if role with the same name already exists
        if UserRole.objects.filter(Q(user_role_name__exact=user_role_name.upper()) & Q(organization_id=organization_id)).exists():
            return Response({'error': {'message':'Role with the same name already exists',
                'status_code':status.HTTP_404_NOT_FOUND,
                }}, status=status.HTTP_400_BAD_REQUEST)
        
        user_role = UserRole.objects.create(
            user_role_name=user_role_name.upper(),
            organization_id=organization_id,
            description=description,
            priority=priority,
            role_status=role_status,
            module_name=module_name,
            permissions=permissions,
        )
        
        return Response({'result': {'status': 'Created'}})

    # def post(self,request):
    #     data = request.data
    #     res = CheckInput(request,'POST')
    #     if res[0] == 2:
    #         return res[1]
            
    #     user_role_name=data['user_role_name']
    #     module_name=data['module_name']
    #     permissions=data['permissions']

    #     description  =data['description']
    #     priority  =data['priority']
    #     role_status  =data['role_status']


    #     user_role = UserRole.objects.create(
    #         user_role_name=user_role_name,
    #         description  = description,
    #         priority = priority,
    #         role_status = role_status,
    #         module_name=module_name,
    #         permissions=permissions,
    #     )

    #     return Response({'result':{'status':'Created'}})

        
    # def put(self,request,pk):
    #     data = request.data
    #     res = CheckInput(request,'PUT')
    #     if res[0] == 2:
    #         return res[1]
        
    #     update=data['update']
    #     if update == 'ROLE':
    #         user_role_name= data['user_role_name']
    #         role_status  = data['role_status']
    #         description  = data['description']
    #         priority  = data['priority']
         
    #         user_role = UserRole.objects.filter(id=pk).update(
    #             user_role_name=user_role_name,
    #             description  = description,
    #             priority = priority,
    #             role_status = role_status,
    #         )

    #         return Response({'result':{'status':'Updated'}})
    def put(self, request, pk):
        data = request.data
        # res = CheckInput(request, 'PUT')
        # if res[0] == 2:
        #     return res[1]
        key = {'organization_id'}
        check_result, error_response = CheckDataKey(request, key)
        if check_result == 2:
            return error_response

        organization_id = data.get('organization_id')
            
        update = data.get('update')
        if update == 'ROLE':
            user_role_name = data.get('user_role_name')
            role_status = data.get('role_status')
            description = data.get('description')
            priority = data.get('priority')

            
            if UserRole.objects.filter(Q(organization_id=organization_id) & ~Q(id=pk) & Q(user_role_name__exact=user_role_name.upper())).exists():
                return Response({'error': {'message':'Role with the same name already exists',
                'status_code':status.HTTP_404_NOT_FOUND,
                }}, status=status.HTTP_400_BAD_REQUEST)
                
            else:
                user_role = UserRole.objects.filter(Q(organization_id=organization_id) & Q(id=pk)).update(
                    user_role_name=user_role_name.upper(),
                    description=description,
                    priority=priority,
                    role_status=role_status,
                )

                return Response({'result': {'status': 'Updated'}})
                

        if update == 'ACCESSIBILITY':
            
            res = CheckInput(request,'PUT')
            if res[0] == 2:
                return res[1]
            
            module_name=data['module_name']
            permissions=data['permissions']
            role_data = UserRole.objects.get(id=pk)
            main_permission_list = role_data.permissions
            print(role_data.permissions,'role_data.permissions')
            # if len(module_name) >= 1:
            #     index = 0 
            #     for i in role_data.module_name:
                   
            #         if i == module_name[0]:
            #             print(main_permission_list,'111111main_permission_list==>')
            #             main_permission_list[index] = permissions[0]
            #             print(main_permission_list,'222main_permission_list==>')
            #             user_role = UserRole.objects.filter(id=pk).update(permissions = main_permission_list)

            #             return Response({'result':{'status':'Permissions updated !!'}})
            #         index = index +1 
                   
            #     combine_module = list(role_data.module_name) + list(module_name)
            #     combined_permissions = list(role_data.permissions) + list(permissions)

            user_role = UserRole.objects.filter(Q(organization_id=organization_id) & Q(id=pk)).update(
                module_name = module_name,
                permissions  = permissions
            )
        
            return Response({'result':{'status':'Updated'}})
       



           
        else:
            return Response({
                'error':{'message':'update key not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

    def delete(self,request,pk):
        test = (0,{})
        all_values = UserRole.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


@method_decorator([AutorizationRequired], name='dispatch')
class ManagerReviewApiView(APIView):
    
    def get(self,request):
        user_id = request.query_params.get('user_id')
        role_id = request.query_params.get('role_id')
        
        key = {'organization_id'}
        check_result, error_response = CheckGetKey(request, key)
        if check_result == 2:
            return error_response
        organization_id = request.query_params.get('organization_id')

        user_role_data = UserRole.objects.get(id=role_id)
        try:
            user_data = CustomUser.objects.get(Q(organization_id=organization_id) & Q(id=user_id))
        except CustomUser.DoesNotExist:
                return Response({
                'error':{'message':'User does not exists!',
                'description':'Check organization and user linked!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        try:
            user_center_data = Center.objects.get(id=user_data.center_id)
        except Center.DoesNotExist:
                return Response({
                'error':{'message':'Update your center in profile',
                'description':'Manger get data related to his center only!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

        alluser_related_to_manager_center = CustomUser.objects.filter(Q(organization_id=organization_id) & Q(center_id=user_data.center_id))

        emp_list = []
        emp_leave_list =[]
        yet_to_approve_list = []
        approve_list = []
        declined_list = []

        emp_list_timesheet = []
        emp_timesheet_list =[]
        yet_to_approve_list_timesheet = []
        approve_list_timesheet = []
        declined_list_timesheet = []

        if (user_role_data.user_role_name).upper() == "MANAGER" or (user_role_data.user_role_name).upper() == "ADMIN":
            for i in alluser_related_to_manager_center:
                center_data = Center.objects.get(id=i.center_id)
                try:
                    role_data = UserRole.objects.get(id=i.user_role_id)
                except UserRole.DoesNotExist:
                    return Response({
                    'error':{
                        'message':'One of the User role does not exist !',
                        'detail':"User role is mandatory for all user",
                        'status_code':status.HTTP_400_BAD_REQUEST,
                    }},status=status.HTTP_400_BAD_REQUEST)


                emp_info = {
                "user_id":i.id,
                "organization_id":i.organization_id,
                "center_id":i.center_id,
                "center_id":i.center_id,
                "center_name":center_data.center_name,
                "role_id":i.user_role_id,
                "user_role_name":role_data.user_role_name,
                "unique_id":i.u_unique_id,
                "org_code":i.u_org_code,
                "first_name":i.u_first_name,
                "last_name":i.u_last_name,
                "gender":i.u_gender,
                "designation":i.u_designation,
                "date_of_joining":i.u_date_of_joining,
                "profile_path":i.u_profile_path,
                "email":i.u_email,
                "phone_no":i.u_phone_no,
                }
                emp_list.append(emp_info)

                emp_leave_data = leaveApplication.objects.filter(Q(organization_id=organization_id) & Q(user_id=i.id))
                
                for j in emp_leave_data:

                    center_data = Center.objects.get(id=i.center_id)
                    role_data = UserRole.objects.get(id=i.user_role_id)
                    master_leave_data = MasterLeaveTypes.objects.get(id=j.leave_type_id)
                    
                    if j.approved_state == 'YET_TO_APPROVED':
                        yet_to_approve = {
                        "leave_id":j.id,
                        "leave_type_id":j.leave_type_id,
                        "organization_id":i.organization_id,
                        "first_name":i.u_first_name,
                        "last_name":i.u_last_name,
                        "gender":i.u_gender,
                        "leave_title":master_leave_data.leave_title,
                        "user_id":j.user_id,
                        "reason":j.reason,
                        "contact_details":j.contact_details,
                        "leave_application_file_path":j.leave_application_file_path,
                        "cc_to":j.cc_to,
                        "leaveApplication_from_date":j.leaveApplication_from_date,
                        "leaveApplication_to_date":j.leaveApplication_to_date,
                        "days":j.days,
                        "from_session":j.from_session,
                        "to_session":j.to_session,
                        "balance":j.balance,
                        "c_timestamp":j.c_timestamp,
                        "m_timestamp":j.m_timestamp,
                        "approved_by_id":j.approved_by_id,
                        "approved_date":j.approved_date,
                        "approved_state":j.approved_state,
                        "sort":j.sort,
                        }
                        yet_to_approve_list.append(yet_to_approve)

                        
                    elif j.approved_state == 'APPROVED':
                        approve = {
                        "leave_id":j.id,
                        "leave_type_id":j.leave_type_id,
                        "organization_id":i.organization_id,
                        "first_name":i.u_first_name,
                        "last_name":i.u_last_name,
                        "gender":i.u_gender,
                        "leave_title":master_leave_data.leave_title,
                        "user_id":j.user_id,
                        "reason":j.reason,
                        "contact_details":j.contact_details,
                        "leave_application_file_path":j.leave_application_file_path,
                        "cc_to":j.cc_to,
                        "leaveApplication_from_date":j.leaveApplication_from_date,
                        "leaveApplication_to_date":j.leaveApplication_to_date,
                        "days":j.days,
                        "from_session":j.from_session,
                        "to_session":j.to_session,
                        "balance":j.balance,
                        "c_timestamp":j.c_timestamp,
                        "m_timestamp":j.m_timestamp,
                        "approved_by_id":j.approved_by_id,
                        "approved_date":j.approved_date,
                        "approved_state":j.approved_state,
                        "sort":j.sort,
                        }
                        approve_list.append(approve)

                    else:
                        declined = {
                        "leave_id":j.id,
                        "leave_type_id":j.leave_type_id,
                        "organization_id":i.organization_id,
                        "first_name":i.u_first_name,
                        "last_name":i.u_last_name,
                        "gender":i.u_gender,
                        "leave_title":master_leave_data.leave_title,
                        "user_id":j.user_id,
                        "reason":j.reason,
                        "contact_details":j.contact_details,
                        "leave_application_file_path":j.leave_application_file_path,
                        "cc_to":j.cc_to,
                        "leaveApplication_from_date":j.leaveApplication_from_date,
                        "leaveApplication_to_date":j.leaveApplication_to_date,
                        "days":j.days,
                        "from_session":j.from_session,
                        "to_session":j.to_session,
                        "balance":j.balance,
                        "c_timestamp":j.c_timestamp,
                        "m_timestamp":j.m_timestamp,
                        "approved_by_id":j.approved_by_id,
                        "approved_date":j.approved_date,
                        "approved_state":j.approved_state,
                        "sort":j.sort,
                        }
                        declined_list.append(declined)
                
                # Timesheet
                emp_timesheet_data = TimeSheets.objects.filter(Q(organization_id=organization_id) & Q(created_by_id=i.id))
                
                for k in emp_timesheet_data:

                    # center_data = Center.objects.get(id=i.center_id)
                    # role_data = UserRole.objects.get(id=i.user_role_id)
                    # master_leave_data = MasterLeaveTypes.objects.get(id=k.leave_type_id)
                    client_data = Clients.objects.get(id=k.client_id)
                    project_data = Projects.objects.get(id=k.project_id)
                    custom_user_data = CustomUser.objects.get(id=k.created_by_id)
                    
                    if k.approved_state == 'YET_TO_APPROVED':
                        yet_to_approve_timesheet = {
                            'timesheet_id': k.id,
                            # client
                            "client_id":k.client_id,
                            "client_name":client_data.c_name,
                            "org_ref_id":client_data.org_ref_id,
                            "user_ref_id":client_data.user_ref_id,
                            "toi_ref_id":client_data.toi_ref_id,
                            "c_contact_person":client_data.c_contact_person,
                            "c_satus":client_data.c_satus,
                            "client_projects":client_data.project,
                            
                            # project
                            "project_id":k.project_id,
                            "org_ref_id":project_data.org_ref_id,
                            "user_ref_id":project_data.user_ref_id,
                            "c_ref_id":project_data.c_ref_id,
                            "reporting_manager_ref_id":project_data.reporting_manager_ref_id,
                            "approve_manager_ref_id":project_data.approve_manager_ref_id,
                            "opg_ref_id":project_data.opg_ref_id,
                            "pc_ref_id":project_data.pc_ref_id,
                            "people_ref_list":project_data.people_ref_list,
                            "p_description":project_data.p_description,
                            "p_name":project_data.p_name,
                            "p_people_type":project_data.p_people_type,
                            "p_start_date":project_data.p_start_date,
                            "p_closure_date":project_data.p_closure_date,
                            "p_task_checklist_status":project_data.p_task_checklist_status,
                            "p_status":project_data.p_status,

                            # custom_user
                            "created_by_id":k.created_by_id,
                            # "super_user_ref_id":custom_user_data.super_user_ref_id,
                            "center_id":custom_user_data.center_id,
                            "user_role_id":custom_user_data.user_role_id,
                            "organization_id":custom_user_data.organization_id,
                            "first_name":custom_user_data.u_first_name,
                            "last_name":custom_user_data.u_last_name,
                            # "u_gender":custom_user_data.u_gender,
                            # "u_email":custom_user_data.u_email,
                            # "u_phone_no":custom_user_data.u_phone_no,
                            # "u_state":custom_user_data.u_state,
                            # "u_city":custom_user_data.u_city,
                            # "u_dob":custom_user_data.u_dob,

                            "reporting_manager_ref_id":k.reporting_manager_ref_id,
                            "approved_by_id":k.approved_by_id,
                            "project_category":k.project_category,
                            "time_spent":k.time_spent,
                            "description":k.description,
                            "task_worked_list":k.task_worked_list,
                            "approved_state":k.approved_state,
                            "sort":k.sort,
                            "applied_date":k.applied_date,
                            "applied_date_timestamp":k.applied_date_timestamp,
                            "approved_date_timestamp":k.approved_date_timestamp,
                            "approved_date_time":k.approved_date_time,
                            "created_date_time":k.created_date_time,
                        }
                        yet_to_approve_list_timesheet.append(yet_to_approve_timesheet)

                        
                    elif k.approved_state == 'APPROVED':
                        approve_timesheet = {
                            'timesheet_id': k.id,
                            # client
                            "client_id":k.client_id,
                            "client_name":client_data.c_name,
                            "org_ref_id":client_data.org_ref_id,
                            "user_ref_id":client_data.user_ref_id,
                            "toi_ref_id":client_data.toi_ref_id,
                            "c_contact_person":client_data.c_contact_person,
                            "c_satus":client_data.c_satus,
                            "client_projects":client_data.project,
                            
                            # project
                            "project_id":k.project_id,
                            "org_ref_id":project_data.org_ref_id,
                            "user_ref_id":project_data.user_ref_id,
                            "c_ref_id":project_data.c_ref_id,
                            "reporting_manager_ref_id":project_data.reporting_manager_ref_id,
                            "approve_manager_ref_id":project_data.approve_manager_ref_id,
                            "opg_ref_id":project_data.opg_ref_id,
                            "pc_ref_id":project_data.pc_ref_id,
                            "people_ref_list":project_data.people_ref_list,
                            "p_description":project_data.p_description,
                            "p_name":project_data.p_name,
                            "p_people_type":project_data.p_people_type,
                            "p_start_date":project_data.p_start_date,
                            "p_closure_date":project_data.p_closure_date,
                            "p_task_checklist_status":project_data.p_task_checklist_status,
                            "p_status":project_data.p_status,

                            # custom_user
                            "created_by_id":k.created_by_id,
                            # "super_user_ref_id":custom_user_data.super_user_ref_id,
                            "center_id":custom_user_data.center_id,
                            "user_role_id":custom_user_data.user_role_id,
                            "organization_id":custom_user_data.organization_id,
                            "first_name":custom_user_data.u_first_name,
                            "last_name":custom_user_data.u_last_name,
                            # "u_gender":custom_user_data.u_gender,
                            # "u_email":custom_user_data.u_email,
                            # "u_phone_no":custom_user_data.u_phone_no,
                            # "u_state":custom_user_data.u_state,
                            # "u_city":custom_user_data.u_city,
                            # "u_dob":custom_user_data.u_dob,

                            "reporting_manager_ref_id":k.reporting_manager_ref_id,
                            "approved_by_id":k.approved_by_id,
                            "project_category":k.project_category,
                            "time_spent":k.time_spent,
                            "description":k.description,
                            "task_worked_list":k.task_worked_list,
                            "approved_state":k.approved_state,
                            "sort":k.sort,
                            "applied_date":k.applied_date,
                            "applied_date_timestamp":k.applied_date_timestamp,
                            "approved_date_timestamp":k.approved_date_timestamp,
                            "approved_date_time":k.approved_date_time,
                            "created_date_time":k.created_date_time,
                        }
                        approve_list_timesheet.append(approve_timesheet)

                    else:
                        declined_timesheet = {
                            'timesheet_id': k.id,
                            # client
                            "client_id":k.client_id,
                            "client_name":client_data.c_name,
                            "org_ref_id":client_data.org_ref_id,
                            "user_ref_id":client_data.user_ref_id,
                            "toi_ref_id":client_data.toi_ref_id,
                            "c_contact_person":client_data.c_contact_person,
                            "c_satus":client_data.c_satus,
                            "client_projects":client_data.project,
                            
                            # project
                            "project_id":k.project_id,
                            "org_ref_id":project_data.org_ref_id,
                            "user_ref_id":project_data.user_ref_id,
                            "c_ref_id":project_data.c_ref_id,
                            "reporting_manager_ref_id":project_data.reporting_manager_ref_id,
                            "approve_manager_ref_id":project_data.approve_manager_ref_id,
                            "opg_ref_id":project_data.opg_ref_id,
                            "pc_ref_id":project_data.pc_ref_id,
                            "people_ref_list":project_data.people_ref_list,
                            "p_description":project_data.p_description,
                            "p_name":project_data.p_name,
                            "p_people_type":project_data.p_people_type,
                            "p_start_date":project_data.p_start_date,
                            "p_closure_date":project_data.p_closure_date,
                            "p_task_checklist_status":project_data.p_task_checklist_status,
                            "p_status":project_data.p_status,

                            # custom_user
                            "created_by_id":k.created_by_id,
                            # "super_user_ref_id":custom_user_data.super_user_ref_id,
                            "center_id":custom_user_data.center_id,
                            "user_role_id":custom_user_data.user_role_id,
                            "organization_id":custom_user_data.organization_id,
                            "first_name":custom_user_data.u_first_name,
                            "last_name":custom_user_data.u_last_name,
                            # "u_gender":custom_user_data.u_gender,
                            # "u_email":custom_user_data.u_email,
                            # "u_phone_no":custom_user_data.u_phone_no,
                            # "u_state":custom_user_data.u_state,
                            # "u_city":custom_user_data.u_city,
                            # "u_dob":custom_user_data.u_dob,

                            "reporting_manager_ref_id":k.reporting_manager_ref_id,
                            "approved_by_id":k.approved_by_id,
                            "project_category":k.project_category,
                            "time_spent":k.time_spent,
                            "description":k.description,
                            "task_worked_list":k.task_worked_list,
                            "approved_state":k.approved_state,
                            "sort":k.sort,
                            "applied_date":k.applied_date,
                            "applied_date_timestamp":k.applied_date_timestamp,
                            "approved_date_timestamp":k.approved_date_timestamp,
                            "approved_date_time":k.approved_date_time,
                            "created_date_time":k.created_date_time,
                        }
                        declined_list_timesheet.append(declined_timesheet)

            emp_leave_timesheet = {
                "yet_to_approve":yet_to_approve_list_timesheet,
                "approve":approve_list_timesheet,
                "declined":declined_list_timesheet,
            }
            emp_timesheet_list.append(emp_leave_timesheet)

            emp_leave = {
                "yet_to_approve":yet_to_approve_list,
                "approve":approve_list,
                "declined":declined_list,
            }
            emp_leave_list.append(emp_leave)

               


            result = {
                "manger_info":{
                    "user_id":user_id,
                    "organization_id":user_data.organization_id,
                    "center_id":user_data.center_id,
                    "center_name":user_center_data.center_name,
                    "role_id":user_data.user_role_id,
                    "user_role_name":user_role_data.user_role_name,
                    "unique_id":user_data.u_unique_id,
                    "org_code":user_data.u_org_code,
                    "first_name":user_data.u_first_name,
                    "last_name":user_data.u_last_name,
                    "gender":user_data.u_gender,
                    "designation":user_data.u_designation,
                    "date_of_joining":user_data.u_date_of_joining,
                    "profile_path":user_data.u_profile_path,
                    "email":user_data.u_email,
                    "phone_no":user_data.u_phone_no,
                },
                "emp_info_list":emp_list,
                "emp_leave_list":emp_leave_list,
                "emp_timesheet_list":emp_timesheet_list,
            }
        
        
            return Response({'result':{'status':'GET','data':result}})

        else:
            return Response({
                    'error':{'message':'You are not authorized to perform this operation.',
                    'description':"you are not a MANAGER",
                    'status_code':status.HTTP_401_UNAUTHORIZED,
                    }},status=status.HTTP_401_UNAUTHORIZED) 

    def post(self,request):
        data = request.data
       
        return Response({'result':{'status':'Created'}})

    def put(self,request,pk):
        data = request.data
   
        return Response({'result':{'status':'Updated'}})
    
    def delete(self,request,pk):
        test = (0,{})
        all_values = UserRole.objects.filter(id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})



@method_decorator([AutorizationRequired], name='dispatch')
class AddOnLeaveRequestApiView(APIView):
    def get(self,request):
        res = GetCheckPermission(request)
        if res[0] == 2:
            return res[1]
        print(res,'res=====>')
        id = request.query_params.get('id')
        user_id= request.query_params.get('user_id')
        approved_state = request.query_params.get('approved_state')
        lfd= request.query_params.get('leaveApplication_from_date')
        ltd= request.query_params.get('leaveApplication_to_date')

        page_number = request.query_params.get('page_number')
        data_per_page = request.query_params.get('data_per_page')
        if (page_number == None) | (page_number == '') | (data_per_page ==None ) | (data_per_page == '') :
            return Response({
                'error':{'message':'page_number or data_per_page parameter missing!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)


        pagination = request.query_params.get('pagination')
        if pagination == 'FALSE':
            all_data = leaveApplication.objects.all().values().order_by('-id')
            return Response({'result':{'status':'GET all without pagination','data':all_data}})

        if id:
            
            all_data = leaveApplication.objects.filter(id=id).values().order_by('-id')
            if not all_data:
                return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)

            return Response({'result':{'status':'GET by Id','data':all_data}})


        if lfd:
            from_date = time.mktime(datetime.datetime.strptime(lfd, "%d/%m/%Y").timetuple())
            to_date = time.mktime(datetime.datetime.strptime(ltd, "%d/%m/%Y").timetuple())
            print(from_date,'from_date==>')
            print(to_date,'to_date==>')
            leave_data = leaveApplication.objects.filter(Q(approved_state=approved_state) & Q(user_id=user_id) & Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date) & Q(request = 'ADD_ON_LEAVE_REQUEST')).values().order_by('-id')

            yet_to_be_approved_count = leaveApplication.objects.filter(Q(approved_state='YET_TO_APPROVED') & Q(user_id=user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST')& Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date)).count()
            approved_count = leaveApplication.objects.filter(Q(approved_state='APPROVED') & Q(user_id=user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST')& Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date)).count()
            declined_count = leaveApplication.objects.filter(Q(approved_state='DECLINED') & Q(user_id=user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST') & Q(leaveApplication_from_date__gte=from_date) & Q(leaveApplication_to_date__lte=to_date)).count()
            
            all_count = {
                'request_count':yet_to_be_approved_count,
                'approved_count':approved_count,
                'declined_count':declined_count,
            }

            # leave_data = leaveApplication.objects.filter(Q(user_id = user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST')).values().order_by('-id')
            data_pagination = EztimeAppPagination(leave_data,page_number,data_per_page,request)

            return Response({'result':{'status':'Get by ApprovedState',
                'add_on_leave_dashboard':all_count,
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
            
            leave_data = leaveApplication.objects.filter(Q(approved_state=approved_state) & Q(user_id=user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST')).values().order_by('-id')

            yet_to_be_approved_count = leaveApplication.objects.filter(Q(approved_state='YET_TO_APPROVED') & Q(user_id=user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST')).count()
            approved_count = leaveApplication.objects.filter(Q(approved_state='APPROVED') & Q(user_id=user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST')).count()
            declined_count = leaveApplication.objects.filter(Q(approved_state='DECLINED') & Q(user_id=user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST') ).count()
            
            all_count = {
                'request_count':yet_to_be_approved_count,
                'approved_count':approved_count,
                'declined_count':declined_count,
            }

            # leave_data = leaveApplication.objects.filter(Q(user_id = user_id) & Q(request = 'ADD_ON_LEAVE_REQUEST')).values().order_by('-id')
            data_pagination = EztimeAppPagination(leave_data,page_number,data_per_page,request)

            return Response({'result':{'status':'Get by ApprovedState',
                'add_on_leave_dashboard':all_count,
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


    def post(self,request):
        data = request.data
        res = CheckPermission(request)
        if res[0] == 2:
            return res[1]
        print(res,'res=====>')
        leave_type=data['leave_type_id']
        user_id = data['user_id']
        reason=data['reason']
        # contact_details=data['contact_details']
        
        # cc_to=data['cc_to']
        lfd=data['leaveApplication_from_date']
        ltd=data['leaveApplication_to_date']
        days=data['days']
        from_session=data['from_session']
        to_session=data['to_session']
        balance=data['balance']
        
        leaveApplication_from_date = time.mktime(datetime.datetime.strptime(lfd, "%d/%m/%Y").timetuple())
        print(leaveApplication_from_date,'stamppppppppppppppp')

        leaveApplication_to_date = time.mktime(datetime.datetime.strptime(ltd, "%d/%m/%Y").timetuple())
        print(leaveApplication_to_date,'stamppppppppppppppp')
        
        
        # if leaveApplication.objects.filter(Q(user_id=user_id) & Q(leaveApplication_from_date=leaveApplication_from_date) & Q(leaveApplication_to_date=leaveApplication_to_date)).exists():
        #     return Response({
        #     'error':{'message':'You already applied for leave on this day',
        #     'hint':'check my leave section to know abount you current leave',
        #     'status_code':status.HTTP_400_BAD_REQUEST,
        #     }},status=status.HTTP_400_BAD_REQUEST)
        if leaveApplication.objects.filter(Q(user_id=user_id)& ~Q(approved_state="DECLINED")).exists():
            leave_data = leaveApplication.objects.filter(Q(user_id=user_id)& ~Q(approved_state="DECLINED"))
            for k in leave_data:
                if float(leaveApplication_from_date) >= float(k.leaveApplication_from_date):
                    print("150 > 100 DB",k.id)
                    if float(leaveApplication_from_date)<= float(k.leaveApplication_to_date):
                        print("150 < 200 DB")
                        return Response({
                            'error':{'message':'You already applied for leave on this day',
                            'hint':'check my leave section to know abount you current leave dates',
                            'description':'Check all date you applied leaves',
                            'status_code':status.HTTP_400_BAD_REQUEST,
                            }},status=status.HTTP_400_BAD_REQUEST)
                    else:
                        print("250 > 200 DB",k.id)
                        
                if float(leaveApplication_from_date) <= float(k.leaveApplication_from_date):
                    print("150 < 200 DB",k.id)
                    if float(leaveApplication_to_date) <= float(k.leaveApplication_from_date):
                        print("150 < 200 DB",k.id)
                    else:
                        return Response({
                        'error':{'message':'You already applied for leave on this day',
                        'hint':'check my leave section to know abount you current leave',
                        'status_code':status.HTTP_400_BAD_REQUEST,
                        }},status=status.HTTP_400_BAD_REQUEST)

        try:

            file_stored_path = '/eztime/django/site/media/leave_files/'
            project_base_url = 'https://projectaceuat.thestorywallcafe.com/'
            leave_application_file_attachment=data.get('leave_application_file_attachment')

            if leave_application_file_attachment != '':
                stored_path = StoreBase64ReturnPath(leave_application_file_attachment, file_stored_path, project_base_url)
                leaveApplication.objects.create(leave_type_id=leave_type,
                user_id=user_id,
                                                reason=reason,
                                                # contact_details=contact_details,
                                                leave_application_file_path=stored_path,
                                                # cc_to=cc_to,
                                                leaveApplication_from_date=leaveApplication_from_date,
                                                leaveApplication_to_date=leaveApplication_to_date,
                                                days=days,
                                                from_session=from_session,
                                                to_session=to_session,
                                                balance=balance,
                                                approved_state='YET_TO_APPROVED',
                                                request="ADD_ON_LEAVE_REQUEST",
                                                )
            else:

                leaveApplication.objects.create(leave_type_id=leave_type,
                user_id=user_id,
                                                reason=reason,
                                                # contact_details=contact_details,
                                                # cc_to=cc_to,
                                                leaveApplication_from_date=leaveApplication_from_date,
                                                leaveApplication_to_date=leaveApplication_to_date,
                                                days=days,
                                                from_session=from_session,
                                                to_session=to_session,
                                                balance=balance,
                                                approved_state='YET_TO_APPROVED',
                                                request="ADD_ON_LEAVE_REQUEST",
                                                )


            return Response({'result':{'status':'Created'}})
        
        except IntegrityError as e:
            error_message = e.args
            return Response({
            'error':{'message':'DB error!',
            'detail':error_message,
            'status_code':status.HTTP_400_BAD_REQUEST,
            }},status=status.HTTP_400_BAD_REQUEST)



@method_decorator([AutorizationRequired], name='dispatch')
class OfficeWorkingDaysApiView(APIView):
    def get(self,request):
        all_keys = {'organization_id'}
        if all_keys <= request.query_params.keys():
            organization_id = request.query_params.get('organization_id')
            try:
                org = OfficeWorkingDays.objects.get(Q(organization_id = organization_id))
                org_data = {
                    'id':org.id,
                    "updated_by_id":org.updated_by_id,
                    "office_working_days_all":org.office_working_days_all,
                    "office_working_days":org.office_working_days,
                    "created_time":org.created_time,
                    "updated_time":org.updated_time,
                }
                return Response({'result':'Get_by_id','status':'HTTP_200_OK','data':org_data})

            except OfficeWorkingDays.DoesNotExist:
                return Response({
                'error':{'message':'Office Working Days for this organization not exists',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
           
        
        else:
            org = OfficeWorkingDays.objects.all().values().order_by('-id')

            missing_keys = all_keys - request.query_params.keys()
            return Response({
                'error':{'message':'Key missing!',
                'description':str(missing_keys) + " key is mandatory",
                'status_code':status.HTTP_404_NOT_FOUND,
                'all_data':org,
                }},status=status.HTTP_404_NOT_FOUND)

    def post(self,request):
        res = CheckOfficeWorkingDaysInput(request)
        if res[0] == 2:
            return res[1]

        data = request.data
        organization_id = data["organization_id"]
        updated_by_id = data["updated_by_id"]
        office_working_days_all = data["office_working_days_all"]

        if OfficeWorkingDays.objects.filter(Q(organization_id=organization_id)).exists():
            
            OfficeWorkingDays.objects.filter(Q(organization_id=organization_id)).update(
            organization_id=organization_id,
            updated_by_id=updated_by_id,
            office_working_days_all=office_working_days_all
            )
            return Response({'result': {'status': 'Office Working Days Updated successfully!!'}})

        else:

            OfficeWorkingDays.objects.create(
                organization_id=organization_id,
                updated_by_id=updated_by_id,
                office_working_days_all=office_working_days_all
            )
            
            return Response({'result': {'status': 'Office Working Days created successfully!!'}})
   
    def put(self,request,pk):
        data = request.data
   
        return Response({'result':{'status':'Updated'}})
    
    def delete(self,request,pk):
        test = (0,{})
        all_values = OfficeWorkingDays.objects.filter(organization_id=pk).delete()
        if test == all_values:
            return Response({
                'error':{'message':'Record not found!',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'result':{'status':'deleted'}})


import requests
@method_decorator([AutorizationRequired], name='dispatch')
class CountryStateCityApiView(APIView):

    def post(self,request):
        result ={}

        data = request.data
        data_request = data["data_request"]
        
        # get token

        base_url = 'https://www.universal-tutorial.com/api/getaccesstoken'
        headers = {
            'api-token':'2F-6txE_FZ7cQSx-0rnRz7iXgS_Q71iTQkhYDTLng8k2BKUTUuPIzhY-9Taf1Gd7G6k',
            'user-email':'farhana@ekfrazo.in'
        }

        res_data = requests.get(url=base_url,headers=headers)
        status_code = res_data.status_code
        response = res_data.json()
    
        if status_code == 502:
            result['message'] = "Try after sometime"
            result['data'] = response
            result['status'] = status
            
        else:
            result['message'] = "Data fetched successfully!"
            # result['data'] = response['auth_token']
            # result['status'] = status
            


        if data_request == "GIVE_ALL_COUNTRY":
            country_base_url = "https://www.universal-tutorial.com/api/countries/"
            headers = {
                'Authorization': 'Bearer '+str(response['auth_token'])
            }
            res_data = requests.get(url=country_base_url,headers=headers)
            status_code = res_data.status_code
            response_data = res_data.json()
            print("response====>",response_data)
            result['data'] = response_data
        
        if data_request == "GIVE_COUNTRY_RELATED_STATE":
            all_keys = {'country_name','data_request'}
            if all_keys <= request.data.keys():
                country_name = data["country_name"]
                country_base_url = "https://www.universal-tutorial.com/api/states/"+str(country_name)
                headers = {
                    'Authorization': 'Bearer '+str(response['auth_token'])
                }
                res_data = requests.get(url=country_base_url,headers=headers)
                status_code = res_data.status_code
                response_data = res_data.json()
                result['data'] = response_data

            else:
                missing_keys = all_keys - request.data.keys()
                return Response({
                    'error':{'message':'Key missing!',
                    'description':str(missing_keys) + " key is mandatory",
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)

            
        if data_request == "GIVE_STATE_RELATED_CITY":
            all_keys = {'state_name','data_request'}
            if all_keys <= request.data.keys():
                state_name = data["state_name"]
                state_base_url = "https://www.universal-tutorial.com/api/cities/"+str(state_name)
                headers = {
                    'Authorization': 'Bearer '+str(response['auth_token'])
                }
                res_data = requests.get(url=state_base_url,headers=headers)
                status_code = res_data.status_code
                response_data = res_data.json()
                result['data'] = response_data
            else:
                missing_keys = all_keys - request.data.keys()
                return Response({
                    'error':{'message':'Key missing!',
                    'description':str(missing_keys) + " key is mandatory",
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)

        # return Response({'result': {'status': 'Get data!!','data':result}})

        if status_code == 200:
            return Response({'result': {'status': 'Get data!!','data':result}},status= status.HTTP_200_OK)
          
        else:
            return Response({'result': {'status': 'Get data!!','data':result}},status= status.HTTP_502_BAD_GATEWAY)


        # result = data[0]['auth_token']
   
# return Response(response_result['result'], headers=response,status= status.HTTP_200_OK)

def check_authorization_header(request):
    auth_header = request.headers.get('Authorization', 'No Authorization header found')
    auth_header_all = dict(request.headers)  # Convert request.headers to a dictionary
    return JsonResponse({'Authorization': auth_header, 'all_headers': auth_header_all})
