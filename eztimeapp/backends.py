# import jwt
# from rest_framework import authentication, exceptions,status
# from django.conf import settings
# from django.contrib.auth.models import User
# # from .base_import import *
# from rest_framework.response import Response
# from rest_framework.views import APIView
# # class JWTAuthentication(APIView):

# def CheckAuth(request):
#     try:
#         if ('Authorization' in request.headers) and (len(request.headers['Authorization']) != 0):
#             pass
#         else:
#             raise exceptions.AuthenticationFailed({'error': {'code':'AUTHENTICATION_FAILURE','message':'You are not authorized to perform this operation. '}})

#         auth_data = request.headers['Authorization']
#         if not auth_data:
#             raise exceptions.AuthenticationFailed({'error': {'code':'INVALID_HEADER_FORMAT','message':'you must be passed as authorization header '}})
#         if "Bearer " not in auth_data:
#             raise exceptions.AuthenticationFailed({'error': {'code':'INVALID_TOKEN_FORMAT','message':'check the token format '}})
#         auth_data = auth_data.split(' ')[1]


#     except IndexError as e:
#         return Response({'error':{'message':e}})

#     try:
#         print(settings.JWT_SECRET_KEY,'==========secret-key===========')
#         payload = jwt.decode(auth_data, str(settings.JWT_SECRET_KEY), algorithms="HS256")
#         # payload_email = payload['email']
#         # user = User.objects.get(username=payload_email)
#         return 1

#     except jwt.DecodeError as identifier:
#         raise exceptions.AuthenticationFailed({'error': {"code": "AUTHENTICATION_FAILURE",'message':'You token is not valid'}})
#     except jwt.ExpiredSignatureError as identifier:
#         raise exceptions.AuthenticationFailed({'error': {"code": "AUTHENTICATION_FAILURE",'message':'token expired!,enter valid token'}})

# ######################### updated auth code for eztime #####################

# from os import O_TMPFILE
from django.http.response import HttpResponse, JsonResponse
from django.shortcuts import render
import jwt
from rest_framework import authentication, exceptions, status
from eztimeapp.models import *
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from django.http import HttpRequest
from functools import wraps

import base64
import random
import re
from mimetypes import guess_extension
import http.client
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import *
from django.db.models import Q

def CheckAuthData(request):
    print("==========================header", request.headers)
    try:
        if ('Authorization' in request.headers) and (len(request.headers['Authorization']) != 0):
            pass
            print("============", request.headers['Authorization'])
        else:
            raise exceptions.AuthenticationFailed(
                {'error': {'code': 'AUTHENTICATION_FAILURE', 'message': 'You are not authorized to perform this operation. '}})

        auth_data = request.headers['Authorization']
        if not auth_data:
            raise exceptions.AuthenticationFailed(
                {'error': {'code': 'INVALID_HEADER_FORMAT', 'message': 'you must be passed as Authorisation header '}})
        if "Bearer " not in auth_data:
            raise exceptions.AuthenticationFailed(
                {'error': {'code': 'INVALID_TOKEN_FORMAT', 'message': 'check the token format '}})
        auth_data = auth_data.split(' ')[1]

    except IndexError as e:
        return Response({'error': {'message': e}})

    try:
        print(settings.JWT_SECRET_KEY, '====hello======secret-key===========')
        payload = jwt.decode(auth_data, str(
            settings.JWT_SECRET_KEY), algorithms="HS256")
        payload_id = payload['user_id']
        print(payload_id)
        user_id = CustomUser.objects.get(id=payload_id)
        return user_id

    except jwt.DecodeError as identifier:
        raise exceptions.AuthenticationFailed(
            {'error': {"code": "AUTHENTICATION_FAILURE", 'message': 'You token is not valid'}})
    except jwt.ExpiredSignatureError as identifier:
        raise exceptions.AuthenticationFailed(
            {'error': {"code": "AUTHENTICATION_FAILURE", 'message': 'token expired!,enter valid token'}})


def authorization_required(func):
    def checkAuthData(request, *args, **kwargs):
        print("request==>>header=", kwargs)
        try:
            if ('Authorization' in request.headers) and (len(request.headers['Authorization']) != 0):
                pass
            else:
                # raise exceptions.AuthenticationFailed(
                #     {'error': {'code': 'AUTHENTICATION_FAILURE', 'message': 'You are not authorized to perform this operation. '}})
                # return render(request, 'error-page.html', status=status.HTTP_401_UNAUTHORIZED)
                return JsonResponse({'error': {'code': 'AUTHENTICATION_FAILURE', 'message': 'You are not authorized to perform this operation. '}}, status=status.HTTP_401_UNAUTHORIZED)

            auth_data = request.headers['Authorization']
            if not auth_data:
                return JsonResponse(
                    {'error': {'code': 'INVALID_HEADER_FORMAT', 'message': 'you must be passed as Auth header '}}, status=status.HTTP_401_UNAUTHORIZED)
            if "Bearer " not in auth_data:
                return JsonResponse(
                    {'error': {'code': 'INVALID_TOKEN_FORMAT', 'message': 'check the token format '}}, status=status.HTTP_401_UNAUTHORIZED)
            auth_data = auth_data.split(' ')[1]

        except IndexError as e:
            return Response({'error': {'message': e}})

        try:
            print(settings.SECRET_KEY, '======hello2====secret-key===========')
            payload = jwt.decode(auth_data, str(
                settings.JWT_SECRET_KEY), algorithms="HS256")
            payload_id = payload['user_id']
            # print("payload_id",payload_id)
            user_id = User.objects.get(id=payload_id)
            # return user_id
        except jwt.DecodeError as identifier:
            return JsonResponse({'error': {"code": "AUTHENTICATION_FAILURE", 'message': 'You token is not valid'}}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError as identifier:
            return JsonResponse({'error': {"code": "AUTHENTICATION_FAILURE", 'message': 'token expired!,enter valid token'}}, status=status.HTTP_401_UNAUTHORIZED)

        return func(request, *args, **kwargs)
    return checkAuthData


def StoreBase64ReturnPath(file_base64, file_stored_path, project_base_url):

    media_url = project_base_url + 'media' + \
        file_stored_path.split('/media')[1]

    # split_base
    split_base_url_data = file_base64.split(';base64,')[1]
    imgdata1 = base64.b64decode(split_base_url_data)

    # guess_extension
    guess_extension_data = file_base64.split(';')[0].split('/')[1]

    # file_extention
    rand = random.randint(0, 1000)

    print(str(guess_extension_data), '===guess_extension_data===')
    file_path = str(file_stored_path)+str(rand)+'.'+str(guess_extension_data)
    file_extention = str(rand)+'.'+str(guess_extension_data)

    # stored_file_object
    stored_file_object = open(file_path, 'wb')
    stored_file_object.write(imgdata1)
    stored_file_object.close()

    # return file_path_url
    file_path_url = str(media_url)+str(file_extention)

    return file_path_url


def EztimeAppPagination(data, page_number, data_per_page,request):

    base_url = request.build_absolute_uri('?page_number')
    paginator = Paginator(data, data_per_page)
    
    try:
        page = paginator.page(page_number)
    except PageNotAnInteger:
        # If page_number is not an integer, deliver the first page.
        page = paginator.page(1)
    except EmptyPage:
        # If the page_number is out of range, deliver the last page of results.
        page = paginator.page(paginator.num_pages)

    
    # page = paginator.page(page_number)
   
    if page.has_next():
        next_page = int(page_number) + 1
        next_url = str(base_url) + '=' + str(next_page) +'&data_per_page='+str(data_per_page)
    else:
        next_url = None

    if page.has_previous():
        previous_page = int(page_number) - 1
        previous_url = str(base_url) + '=' + str(previous_page) +'&data_per_page='+str(data_per_page)
    else:
        previous_url = None
    try:
        page_obj = paginator.get_page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    
    pagination_object = {
        'current_page':page.number,
        'number_of_pages':paginator.num_pages,
        'next_url':next_url,
        'previous_url':previous_url,
        'next_page_number':page.next_page_number,
        'previous_page_number':page.previous_page_number,
        'has_next':page.has_next(),
        'has_previous':page.has_previous(),
        'has_other_pages':page.has_other_pages(),
    }
   
    return list(page_obj),(pagination_object)

def paginate_data(queryset, page_number, data_per_page, request,organization_id):
    paginator = Paginator(queryset, data_per_page)
    try:
        page_obj = paginator.page(page_number)
    except (PageNotAnInteger, EmptyPage):
        page_obj = paginator.page(1)

    base_url = request.build_absolute_uri('?page_number')
    next_url = None
    previous_url = None

    if page_obj.has_next():
        next_page = int(page_number) + 1
        next_url = f"{base_url}={next_page}&data_per_page={data_per_page}&pagination=TRUE&organization_id={organization_id}"

    if page_obj.has_previous():
        previous_page = int(page_number) - 1
        previous_url = f"{base_url}={previous_page}&data_per_page={data_per_page}&pagination=TRUE&organization_id={organization_id}"

    pagination_object = {
        'current_page': page_obj.number,
        'number_of_pages': paginator.num_pages,
        'next_url': next_url,
        'previous_url': previous_url,
        'has_next': page_obj.has_next(),
        'has_previous': page_obj.has_previous(),
        'has_other_pages': page_obj.has_other_pages(),
    }

    return {
        'data': list(page_obj),
        'pagination': pagination_object
    }


def MySorting(model,request):
    data = request.data
    rearrange = data['rearrange']
    ids = data['ids']

    if len(rearrange) == len(ids):
        print("arrangee==>backend")
        for i,j in zip(rearrange,ids):
            print(i,'iii',j,'jjj')
            if model == 'Center':
                data_count = Center.objects.filter(id=j).update(sort=i)  
            elif model == 'OrganizationRoles':
                data_count = OrganizationRoles.objects.filter(id=j).update(sort=i)  
            else:
                return "2"
        return "1"
    else:
        return "0"


def CheckInput(request,method):
    data = request.data
    print(request.data.keys(),'keyessssssss')
    all_keys = {'permissions','module_name'}
    if all_keys <= request.data.keys():

        permissions=data['permissions']
        module_name=data['module_name']

        module_list = ['LEAVE/HOLIDAY_LIST','TIMESHEET','ACCOUNTS','ROLES','DEPARTMENT','PEOPLE',"INDUSTRY/SECTOR","CLIENTS","PROJECT_STATUS","PROJECT_TASK_CATEGORIES","PROJECTS","REVIEW","ORGANIZATION"]

        set_difference = set(module_list) - set(module_name)
        list_difference_result = list(set_difference)

        set_extra_difference = set(module_name) - set(module_list)
        list_extra_difference_result = list(set_extra_difference)

        if len(list_extra_difference_result) > 0:
            return 2, Response({
                'error':{'message':'These Module key not valid',
                    'description':'We not accept these modules',
                    'hint':"Remove these modules",
                    'extra_modules':list_extra_difference_result,
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)

        # if len(list_difference_result) > 0:
        #     return 2, Response({
        #         'error':{'message':'Modules key value not found',
        #             'description':'All Modules key value is mandatory',
        #             'missing_modules':list_difference_result,
        #             'status_code':status.HTTP_404_NOT_FOUND,
        #             }},status=status.HTTP_404_NOT_FOUND)

        # if data['module'] not in module_list:
        #     return 2, Response({
        #         'error':{'message':'Key module_name value not valid !',
        #         'description':'Enter valid module name',
        #         'status_code':status.HTTP_404_NOT_FOUND,
        #         }},status=status.HTTP_404_NOT_FOUND)

        # if len(module_name) == 1:
        #     if module_name[0] not in module_list:
        #         if method == 'POST':
        #             return 1 ,
        #         else:
        #             return 2,Response({
        #                     'error':{'message':'Key module_name value not valid !',
        #                     'description':'Enter valid module name',
        #                     'status_code':status.HTTP_404_NOT_FOUND,
        #                     }},status=status.HTTP_404_NOT_FOUND)
                    
            
        if len(permissions) > 0:

            for i in module_name:
                # for j in permissions:

                if i == 'LEAVE/HOLIDAY_LIST':
                    all_keys = {"LEAVE_APPLICATION","MY_LEAVES","APPLIED/APPROVIED_LEAVES","ADD_ON_LEAVE_REQUEST","LEAVE_MASTER","OFFICE_WORKING_DAYS"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','APPROVE','REJECT']

                elif i == 'TIMESHEET':
                    all_keys = {"PEOPLE_TIMESHEET","PEOPLE_TIMESHEET_CALENDER","TODAY_APPROVAL_TIMESHEET","MONTH_APPROVAL_TIMESHEET",'DEAD_LINE_CROSSED','APPROVAL_CONFIGURATION'}
                    index = module_name.index(i)
                    access_list = ['CREATE','VIEW','DELETE','ACCEPT','REJECT']

                elif i == 'ACCOUNTS':
                    all_keys = {"ACCOUNTS_MENU","SUBCRIPTION_PLAN"}
                    index = module_name.index(i)
                    access_list = ['VIEW']

                elif i == 'ROLES':
                    all_keys = {"ROLES","ROLES_ACCESSIBILITY"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE','PEOPLE_LIST']

                elif i == 'DEPARTMENT':
                    all_keys = {"DEPARTMENT"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

                elif i == 'PEOPLE':
                    all_keys = {"PEOPLE","PREFIX/SUFFIX","CENTERS","CENTERS_YEAR_LIST","LEAVE_MANAGEMENT","CENTERS_HOLIDAY_LIST","TAGS"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

                elif i == 'INDUSTRY/SECTOR':
                    all_keys = {"INDUSTRY/SECTOR"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

                elif i == 'CLIENTS':
                    all_keys = {"CLIENTS"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

                elif i == 'PROJECT_STATUS':
                    all_keys = {"PROJECT_STATUS","MAIN_CATEGORIES","SUB_CATEGORIES"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

                elif i == 'PROJECT_TASK_CATEGORIES':
                    all_keys = {"PROJECT_TASK_CATEGORIES","CATEGORIES_FILE_TEMPLATE","TASK/CHECKLIST","TASK/CHECKLIST_FILE_TEMPLATE"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

                elif i == 'PROJECTS':
                    all_keys = {"PROJECTS","PROJECTS_FILES","PROJECTS_TASKS/CHECKLIST"}
                    index = module_name.index(i)
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']
                
                elif i == 'REVIEW':
                    all_keys = {"REVIEW"}
                    index = module_name.index(i)
                    access_list = ['VIEW','APPROVE','REJECT']
                
                elif i == 'ORGANIZATION':
                    all_keys = {"ORGANIZATION"}
                    index = module_name.index(i)
                    access_list = ['VIEW','ADD','EDIT','DELETE']

            

                else:
                    return 2, Response({
                        'error':{'message':'You are not authorized to perform this operation.',
                        'description':'Invalid module name !',
                        'status_code':status.HTTP_401_UNAUTHORIZED,
                        }},status=status.HTTP_401_UNAUTHORIZED)
                # first_dic = permissions

                try:
                    first_dic = permissions[index]
                except IndexError as e:
                    return 2, Response({
                        'error':{'message':'Permissions key value not found',
                        'description':f"For this module {i}, Permissions key value is missing",
                        'hint':f"add permissions key value for {i} module",
                        'index_error':f"{e}",
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)

                if all_keys <= first_dic.keys():
                    missing_list = []
                    for i in first_dic.keys():
                        print(first_dic[i],'iiiiiii')
                        if len(first_dic[i]) > 0:
                            # access_list = ['CREATE','UPDATE','VIEW','DELETE','APPROVE','REJECT','ACTIVATE/DEACTIVATE']
                            check_list = []
                            for s in first_dic[i]:
                                print(access_list.count(s),'==========')
                                if s not in check_list:
                                    check_list.append(s)
                                else:
                                    return 2,Response({
                                        'error':{'message':'Key ' + str(i) + ' value is duplicated !',
                                        'description':'duplicate entry not allowed',
                                        'status_code':status.HTTP_404_NOT_FOUND,
                                        }},status=status.HTTP_404_NOT_FOUND)
                                
                                if access_list.count(s) == 1:
                                    print('pass')
                                else:
                                    return 2,Response({
                                        'error':{'message':'Key ' + str(i) + ' value not valid !',
                                        'description':{'key_will_accept_only_these_values':access_list},
                                        'status_code':status.HTTP_404_NOT_FOUND,
                                        }},status=status.HTTP_404_NOT_FOUND)
                                
                        else:
                            print('No data inside key')
                            # return 1 ,

                    print('Checking done')
                    # return 1 ,
                else:
                    
                    missing_keys = all_keys - first_dic.keys()
                    return 2, Response({
                    'error':{'message':f'Permissions key value not found in index {index}',
                    'description':f"For this module {i}, Permissions key value is missing in index {index}",
                    'missing_key':missing_keys,
                    'mandatory_permissions':all_keys,
                    'hint':'Check the module_name and permission index, It should be same',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
                
                        
                    
            return 1 ,
                
        else:
            return 2, Response({
                    'error':{'message':'Permissions key value not found',
                    'description':'Permissions key value is mandatory',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
    else:
        missing_keys = all_keys - request.data.keys()
        return 2, Response({
            'error':{'message':'Key missing!',
            'description':str(missing_keys) + " key is mandatory",
            'status_code':status.HTTP_404_NOT_FOUND,
            }},status=status.HTTP_404_NOT_FOUND)
    
def GetCheckPermission(request):
    data = request.data
    
    print(data.keys(),'data.keys()====>')
    all_keys = {'user_id','module','method','menu'}
    if all_keys <= request.query_params.keys():
        user_id= request.query_params.get('user_id')
        c_user_data = CustomUser.objects.get(id=user_id)
        print(c_user_data.user_role_id,'c_user_data.user_role_id==>')
        if (c_user_data.user_role_id == '') | (c_user_data.user_role_id == None):
            return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            'description':'Your do not have any role, contact admin and make your role clear !',
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED)
        else:
            user_role_data = UserRole.objects.get(id=c_user_data.user_role_id)

            module_list = ['LEAVE/HOLIDAY_LIST','TIMESHEET','ACCOUNTS','ROLES','DEPARTMENT','PEOPLE',"INDUSTRY/SECTOR","CLIENTS","PROJECT_STATUS","PROJECT_TASK_CATEGORIES","PROJECTS","REVIEW","ORGANIZATION"]
            if request.query_params.get('module') not in module_list:
                return 2, Response({
                    'error':{'message':'Key module_name value not valid !',
                    'description':'Enter valid module name',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
            else:   
                if request.query_params.get('module') == 'LEAVE/HOLIDAY_LIST':
                    print("LEAVE/HOLIDAY_LIST====>")
                    all_menu = ["LEAVE_APPLICATION","MY_LEAVES","APPLIED/APPROVIED_LEAVES","ADD_ON_LEAVE_REQUEST","LEAVE_MASTER","OFFICE_WORKING_DAYS"]
                elif request.query_params.get('module') == 'TIMESHEET':
                    print("TIMESHEET====>")
                    all_menu = ["PEOPLE_TIMESHEET","PEOPLE_TIMESHEET_CALENDER","TODAY_APPROVAL_TIMESHEET","MONTH_APPROVAL_TIMESHEET",'DEAD_LINE_CROSSED','APPROVAL_CONFIGURATION']
                elif request.query_params.get('module') == 'ACCOUNTS':
                    print("ACCOUNTS====>")
                    all_menu = ["ACCOUNTS_MENU","SUBCRIPTION_PLAN"]
                elif request.query_params.get('module') == 'ROLES':
                    print("ROLES====>")
                    all_menu = ["ROLES","ROLES_ACCESSIBILITY"]
                elif request.query_params.get('module') == 'DEPARTMENT':
                    print("DEPARTMENT====>")
                    all_menu = ["DEPARTMENT"]
                elif request.query_params.get('module') == 'PEOPLE':
                    print("PEOPLE====>")
                    all_menu = ["PEOPLE","PREFIX/SUFFIX","CENTERS","CENTERS_YEAR_LIST","LEAVE_MANAGEMENT","CENTERS_HOLIDAY_LIST","TAGS"]
                elif request.query_params.get('module') == 'INDUSTRY/SECTOR':
                    print("INDUSTRY/SECTOR====>")
                    all_menu = ["INDUSTRY/SECTOR"]
                elif request.query_params.get('module') == 'CLIENTS':
                    print("CLIENTS====>")
                    all_menu = ["CLIENTS"]
                elif request.query_params.get('module') == 'PROJECT_STATUS':
                    print("PROJECT_STATUS====>")
                    all_menu = ["PROJECT_STATUS","MAIN_CATEGORIES","SUB_CATEGORIES"]
                elif request.query_params.get('module') == 'PROJECT_TASK_CATEGORIES':
                    print("PROJECT_STATUS====>")
                    all_menu = ["PROJECT_TASK_CATEGORIES","CATEGORIES_FILE_TEMPLATE","TASK/CHECKLIST","TASK/CHECKLIST_FILE_TEMPLATE"]
                elif request.query_params.get('module') == 'PROJECTS':
                    print("PROJECTS====>")
                    all_menu = ["PROJECTS","PROJECTS_FILES","PROJECTS_TASKS/CHECKLIST"]
                elif request.query_params.get('module') == 'REVIEW':
                    print("REVIEW====>")
                    all_menu = ["REVIEW"]
                elif request.query_params.get('module') == 'ORGANIZATION':
                    print("ORGANIZATION====>")
                    all_menu = ["ORGANIZATION"]
                else:
                    return 2, Response({
                        'error':{'message':'Key module_name value not valid !',
                        'description':'Enter valid module name',
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)
                # checking
        
                index_1 = 0 
                index=0
                for i in user_role_data.module_name:
                
                    if i == request.query_params.get('module'):
                        print( request.query_params.get('module'),'111111main_permission_list==>')
                        index = index_1
                    index_1 = index_1 +1 
                print(index_1,'index_1======>',index,"index=====>")


                if request.query_params.get('menu') in all_menu:       
                    try:                 
                        permissions = user_role_data.permissions[index][request.query_params.get('menu')]
                    except KeyError:
                        return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            'description':"menu key is invalid",
                            'menu':all_menu,
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED) 
                    
                    if request.query_params.get('method') not in permissions:
                        print('111111111',request.query_params.get('method'),permissions)
                        return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            'description':'check your method key value given',
                            "permission_you_have":permissions,
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED) 
        
                    else:
                        print('222222222',request.query_params.get('method'),permissions)
                        return 1 ,
                else:
                    return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            # 'description':'Your role do not have access for this content',
                            'description':"One of these menu key is mandatory",
                            'menu':all_menu,
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED) 

                # elif request.query_params.get('menu') in all_menu_timesheet:                    
                #     permissions = user_role_data.permissions[index][request.query_params.get('menu')]
                #     print(permissions,'permission===>',request.query_params.get('method'))
                #     print('method===>',request.query_params.get('method'),'-------')
                    
                #     if request.query_params.get('method') not in permissions:
                #         print('111111111',request.query_params.get('method'),permissions)
                #         return 2, Response({
                #             'error':{'message':'You are not authorized to perform this operation.',
                #             'description':'check your method key value given',
                #             "permission_you_have":permissions,
                #             'status_code':status.HTTP_401_UNAUTHORIZED,
                #             }},status=status.HTTP_401_UNAUTHORIZED) 
        
                #     else:
                #         print('222222222',request.query_params.get('method'),permissions)
                #         return 1 ,
                
                
    else:
        missing_keys = all_keys - request.query_params.keys()
        return 2, Response({
            'error':{'message':'Key missing!',
            'description':str(missing_keys) + " key is mandatory",
            'status_code':status.HTTP_404_NOT_FOUND,
            }},status=status.HTTP_404_NOT_FOUND)
    

def CheckPermission(request):
    data = request.data
    # print(data.keys(),'data.keys()====>',data['method'],'methodddd')
    all_keys = {'user_id','module','method','menu'}
    if all_keys <= data.keys():
        user_id= data['user_id']
        c_user_data = CustomUser.objects.get(id=user_id)
        print(c_user_data.user_role_id,'c_user_data.user_role_id==>')
        if (c_user_data.user_role_id == '') | (c_user_data.user_role_id == None):
            return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            'description':'Your do not have any role, contact admin and make your role clear !',
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED)
        else:
            user_role_data = UserRole.objects.get(id=c_user_data.user_role_id)

            module_list = ['LEAVE/HOLIDAY_LIST','ACCOUNTS','TIMESHEET','ROLES','DEPARTMENT','PEOPLE','INDUSTRY/SECTOR','CLIENTS','PROJECT_STATUS',"PROJECT_TASK_CATEGORIES","PROJECTS","REVIEW","ORGANIZATION"]
            if data['module'] not in module_list:
                return 2, Response({
                    'error':{'message':'Key module_name value not valid !',
                    'description':'Enter valid module name',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
            else:
                if data['module'] == 'LEAVE/HOLIDAY_LIST':
                    all_menu = ["LEAVE_APPLICATION","MY_LEAVES","APPLIED/APPROVIED_LEAVES","ADD_ON_LEAVE_REQUEST","LEAVE_MASTER","OFFICE_WORKING_DAYS"]
                elif data['module'] == 'TIMESHEET':
                    all_menu = ["PEOPLE_TIMESHEET","PEOPLE_TIMESHEET_CALENDER","TODAY_APPROVAL_TIMESHEET","MONTH_APPROVAL_TIMESHEET",'DEAD_LINE_CROSSED','APPROVAL_CONFIGURATION']
                elif request.query_params.get('module') == 'ACCOUNTS':
                    print("ACCOUNTS====>")
                    all_menu = ["ACCOUNTS_MENU","SUBCRIPTION_PLAN"]
                elif data['module'] == 'ROLES':
                    print("ROLES====>")
                    all_menu = ["ROLES","ROLES_ACCESSIBILITY"]
                elif data['module'] == 'DEPARTMENT':
                    print("DEPARTMENT====>")
                    all_menu = ["DEPARTMENT"]
                elif data['module'] == 'PEOPLE':
                    print("PEOPLE====>")
                    all_menu = ["PEOPLE","PREFIX/SUFFIX","CENTERS","CENTERS_YEAR_LIST","LEAVE_MANAGEMENT","CENTERS_HOLIDAY_LIST","TAGS"]
                elif data['module'] == 'INDUSTRY/SECTOR':
                    print("INDUSTRY/SECTOR====>")
                    all_menu = ["INDUSTRY/SECTOR"]
                elif data['module'] == 'CLIENTS':
                    print("CLIENTS====>")
                    all_menu = ["CLIENTS"]
                elif data['module'] == 'PROJECT_STATUS':
                    print("PROJECT_STATUS====>")
                    all_menu = ["PROJECT_STATUS","MAIN_CATEGORIES","SUB_CATEGORIES"]
                elif data['module'] == 'PROJECT_TASK_CATEGORIES':
                    print("PROJECT_STATUS====>")
                    all_menu = ["PROJECT_TASK_CATEGORIES","CATEGORIES_FILE_TEMPLATE","TASK/CHECKLIST","TASK/CHECKLIST_FILE_TEMPLATE"]
                elif data['module'] == 'PROJECTS':
                    print("PROJECTS====>")
                    all_menu = ["PROJECTS","PROJECTS_FILES","PROJECTS_TASKS/CHECKLIST"]
                elif data['module'] == 'REVIEW':
                    print("REVIEW====>")
                    all_menu = ["REVIEW"]

                elif data['module'] == 'ORGANIZATION':
                    print("ORGANIZATION====>")
                    all_menu = ["ORGANIZATION"]
                    
                else:
                    return 2, Response({
                    'error':{'message':'Key module_name value not valid !',
                    'description':'Enter valid module name',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)

                

                index_1 = 0 
                index = 0
                for i in user_role_data.module_name:
                
                    if i == data['module']:
                        print( data['module'],'111111main_permission_list==>')
                        index = index_1
                    index_1 = index_1 + 1 
                   

                if data['menu'] in all_menu:
                    try:                    
                        permissions = user_role_data.permissions[index][data['menu']]
                    except KeyError:
                        return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            'description':"menu key is invalid",
                            'menu':all_menu,
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED) 
                    
                    if data['method'] not in permissions:
                        print('111111111',data['method'],permissions)
                        return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            'description':'check your method key value given',
                            "permission_you_have":permissions,
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED) 
        
                    else:
                        print('222222222',data['method'],permissions)
                        return 1 ,
                # elif data['menu'] in all_menu_timesheet:                    
                #     permissions = user_role_data.permissions[index][data['menu']]
                #     print(permissions,'permission===>',data['method'])
                #     print('method===>',data['method'],'-------')
                    
                #     if data['method'] not in permissions:
                #         print('111111111',data['method'],permissions)
                #         return 2, Response({
                #             'error':{'message':'You are not authorized to perform this operation.',
                #             'description':'check your method key value given',
                #             "permission_you_have":permissions,
                #             'status_code':status.HTTP_401_UNAUTHORIZED,
                #             }},status=status.HTTP_401_UNAUTHORIZED) 
        
                #     else:
                #         print('222222222',data['method'],permissions)
                #         return 1 ,
                else:
                    return 2, Response({
                            'error':{'message':'You are not authorized to perform this operation.',
                            # 'description':'Your role do not have access for this content',
                            'description':"One of these menu key is mandatory",
                            'menu':all_menu,
                            'status_code':status.HTTP_401_UNAUTHORIZED,
                            }},status=status.HTTP_401_UNAUTHORIZED) 
    else:
        missing_keys = all_keys - data.keys()
        return 2, Response({
            'error':{'message':'Key missing!',
            'description':str(missing_keys) + " key is mandatory",
            'status_code':status.HTTP_404_NOT_FOUND,
            }},status=status.HTTP_404_NOT_FOUND)


def RearrangeModulePermission(module,permissions):
    # data = request.data
   
    # permissions=data['permissions']
    # module_name=data['module_name']

    module_list = ['LEAVE/HOLIDAY_LIST','TIMESHEET','ACCOUNTS','ROLES','DEPARTMENT','PEOPLE',"INDUSTRY/SECTOR","CLIENTS","PROJECT_STATUS","PROJECT_TASK_CATEGORIES","PROJECTS","REVIEW","ORGANIZATION"]

    set_difference = set(module_list) - set(module)
    list_difference_result = list(set_difference)

    set_extra_difference = set(module) - set(module_list)
    list_extra_difference_result = list(set_extra_difference)

    if len(list_extra_difference_result) > 0:
        return 2, Response({
            'error':{'message':'These Module key not valid',
                'description':'We not accept these modules',
                'hint':"Remove these modules",
                'extra_modules':list_extra_difference_result,
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
 
    rearranged_list = []

    if len(permissions) > 0:

        for i in module:
            # for j in permissions:

            if i == 'LEAVE/HOLIDAY_LIST':
                all_keys = {"LEAVE_APPLICATION","MY_LEAVES","APPLIED/APPROVIED_LEAVES","ADD_ON_LEAVE_REQUEST","LEAVE_MASTER","OFFICE_WORKING_DAYS"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','APPROVE','REJECT']

            elif i == 'TIMESHEET':
                all_keys = {"PEOPLE_TIMESHEET","PEOPLE_TIMESHEET_CALENDER","TODAY_APPROVAL_TIMESHEET","MONTH_APPROVAL_TIMESHEET",'DEAD_LINE_CROSSED','APPROVAL_CONFIGURATION'}
                index = module.index(i)
                access_list = ['CREATE','VIEW','DELETE','ACCEPT','REJECT']

            elif i == 'ACCOUNTS':
                all_keys = {"ACCOUNTS_MENU","SUBCRIPTION_PLAN"}
                index = module.index(i)
                access_list = ['VIEW']

            elif i == 'ROLES':
                all_keys = {"ROLES","ROLES_ACCESSIBILITY"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE','PEOPLE_LIST']

            elif i == 'DEPARTMENT':
                all_keys = {"DEPARTMENT"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

            elif i == 'PEOPLE':
                all_keys = {"PEOPLE","PREFIX/SUFFIX","CENTERS","CENTERS_YEAR_LIST","LEAVE_MANAGEMENT","CENTERS_HOLIDAY_LIST","TAGS"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

            elif i == 'INDUSTRY/SECTOR':
                all_keys = {"INDUSTRY/SECTOR"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

            elif i == 'CLIENTS':
                all_keys = {"CLIENTS"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

            elif i == 'PROJECT_STATUS':
                all_keys = {"PROJECT_STATUS","MAIN_CATEGORIES","SUB_CATEGORIES"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

            elif i == 'PROJECT_TASK_CATEGORIES':
                all_keys = {"PROJECT_TASK_CATEGORIES","CATEGORIES_FILE_TEMPLATE","TASK/CHECKLIST","TASK/CHECKLIST_FILE_TEMPLATE"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']

            elif i == 'PROJECTS':
                all_keys = {"PROJECTS","PROJECTS_FILES","PROJECTS_TASKS/CHECKLIST"}
                index = module.index(i)
                access_list = ['CREATE','UPDATE','VIEW','DELETE','ACTIVATE/DEACTIVATE']
            
            elif i == 'REVIEW':
                all_keys = {"REVIEW"}
                index = module.index(i)
                access_list = ['VIEW','APPROVE','REJECT']

            elif i == 'REVIEW':
                all_keys = {"REVIEW"}
                index = module.index(i)
                access_list = ['VIEW','APPROVE','REJECT']
            
            elif i == 'ORGANIZATION':
                all_keys = {"ORGANIZATION"}
                index = module.index(i)
                access_list = ['VIEW','ADD','EDIT','DELETE']

            else:
                return 2, Response({
                    'error':{'message':'You are not authorized to perform this operation.',
                    'description':'Invalid module name !',
                    'status_code':status.HTTP_401_UNAUTHORIZED,
                    }},status=status.HTTP_401_UNAUTHORIZED)
            # first_dic = permissions

            

            try:
                first_dic = permissions[index]
            except IndexError as e:
                return 2, Response({
                    'error':{'message':'Permissions key value not found',
                    'description':f"For this module {i}, Permissions key value is missing",
                    'hint':f"add permissions key value for {i} module",
                    'index_error':f"{e}",
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
            
            dic_structure = {
                'module_name':i,
                'permissions':first_dic
            }
            rearranged_list.append(dic_structure)

            if all_keys <= first_dic.keys():
                missing_list = []
                for i in first_dic.keys():
                    print(first_dic[i],'iiiiiii')
                    if len(first_dic[i]) > 0:
                        # access_list = ['CREATE','UPDATE','VIEW','DELETE','APPROVE','REJECT','ACTIVATE/DEACTIVATE']
                        check_list = []
                        for s in first_dic[i]:
                            print(access_list.count(s),'==========')
                            if s not in check_list:
                                check_list.append(s)
                            else:
                                return 2,Response({
                                    'error':{'message':'Key ' + str(i) + ' value is duplicated !',
                                    'description':'duplicate entry not allowed',
                                    'status_code':status.HTTP_404_NOT_FOUND,
                                    }},status=status.HTTP_404_NOT_FOUND)
                            
                            if access_list.count(s) == 1:
                                print('pass')
                            else:
                                return 2,Response({
                                    'error':{'message':'Key ' + str(i) + ' value not valid !',
                                    'description':{'key_will_accept_only_these_values':access_list},
                                    'status_code':status.HTTP_404_NOT_FOUND,
                                    }},status=status.HTTP_404_NOT_FOUND)
                            
                    else:
                        print('No data inside key')
                        # return 1 ,

                print('Checking done')
                # return 1 ,
            else:
                
                missing_keys = all_keys - first_dic.keys()
                return 2, Response({
                'error':{'message':f'Permissions key value not found in index {index}',
                'description':f"For this module {i}, Permissions key value is missing in index {index}",
                'missing_key':missing_keys,
                'mandatory_permissions':all_keys,
                'hint':'Check the module_name and permission index, It should be same',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
            
                    
                
        return 1 , rearranged_list
            
    else:
        return 2, Response({
                'error':{'message':'Permissions key value not found',
                'description':'Permissions key value is mandatory',
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)








def CheckOfficeWorkingDaysInput(request):
    data = request.data
    print(request.data.keys(),'keyessssssss')
    all_keys = {"organization_id","updated_by_id","office_working_days_all"}

    if all_keys <= request.data.keys():

        organization_id=data['organization_id']
        updated_by_id=data['updated_by_id']
        office_working_days_all=data['office_working_days_all']
        
        try:
            org = Organization.objects.get(Q(id = organization_id))
            # return 1 ,

        except Organization.DoesNotExist:
            return 2, Response({
            'error':{'message':"Organization does not exists!",
            'hint':"check organization id your passing",
            'status_code':status.HTTP_404_NOT_FOUND,
            }},status=status.HTTP_404_NOT_FOUND)
           
        days_key = {"MONDAY","TUESDAY","WEDNESDAY","THURSDAY","FRIDAY","SATURDAY","SUNDAY"}
        if days_key <= office_working_days_all.keys():
            days_key_list = ["MONDAY","TUESDAY","WEDNESDAY","THURSDAY","FRIDAY","SATURDAY","SUNDAY"]
            inside_days_key = {"from_hr","from_min","to_hr","to_min","total_hours"}
            for k in days_key_list:
                if inside_days_key <= office_working_days_all[k].keys():
                    print("===",office_working_days_all[k].keys())
                else:
                    print(office_working_days_all.get(k),'=================office_working_days_all')
                    if office_working_days_all.get(k) == {} :
                        print("===111")
                    elif office_working_days_all.get(k) == '{}':
                        print("===222")
                    else:
                        missing_keys = inside_days_key - office_working_days_all[k].keys()
                        return 2, Response({
                            'error':{'message':'Key missing!',
                            'description':str(missing_keys) + " key is mandatory in all weeks.",
                            'status_code':status.HTTP_404_NOT_FOUND,
                            }},status=status.HTTP_404_NOT_FOUND)
                
            return 1 ,
            
            

        else:
            missing_keys = days_key - office_working_days_all.keys()
            return 2, Response({
                'error':{'message':'Key missing!',
                'description':str(missing_keys) + " key is mandatory",
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)


        # return 1 ,
                
        
    else:
        missing_keys = all_keys - request.data.keys()
        return 2, Response({
            'error':{'message':'Key missing!',
            'description':str(missing_keys) + " key is mandatory",
            'status_code':status.HTTP_404_NOT_FOUND,
            }},status=status.HTTP_404_NOT_FOUND)
    


def CheckGetKey(request, all_keys):
    query_params = request.query_params
    missing_keys = set(all_keys) - set(query_params.keys())

    error_message = ''

    if missing_keys:
        error_message = f"{missing_keys} key(s) is mandatory"

    if not error_message:
        for i in all_keys:
            key_value = request.query_params.get(i)
            
            if key_value is None:
                error_message += f'None value not allowed for key {i}! '
            elif key_value == "":
                error_message += f'Empty value not allowed for key {i}! '
            elif key_value.upper() == "UNDEFINED":
                error_message += f'Undefined value not allowed for key {i}! '

    if error_message:
        error_response = Response({
            'error': {
                'message': 'Invalid value detected!',
                'description': error_message,
                'status_code': status.HTTP_404_NOT_FOUND,
            }
        }, status=status.HTTP_404_NOT_FOUND)

        return 2, error_response  # Return the check result and the error response

    return 1, None  # Return a success check result and None for the error response


def CheckDataKey(request, all_keys):
    data_keys = set(request.data.keys())

    missing_keys = all_keys - data_keys
    error_message = ''
    
    if missing_keys:
        error_message = f"{missing_keys} key is mandatory"

    if not error_message:
        for i in all_keys:
            if request.data.get(i) == None:
                error_message += 'None value not allowed! '
    
        for i in all_keys:
            if request.data.get(i) == "":
                error_message += 'Empty value not allowed! '
        
    if error_message:
        error_response = Response({
            'error': {
                'message': 'Invalid value detected!',
                'description': error_message,
                'status_code': status.HTTP_404_NOT_FOUND,
            }
        }, status=status.HTTP_404_NOT_FOUND)

        return 2, error_response  # Return the check result and the error response

    return 1, None  # Return a success check result and None for the error response