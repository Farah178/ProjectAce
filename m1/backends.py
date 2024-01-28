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


def MyPagination(data, page_number, data_per_page,request):

    base_url = request.build_absolute_uri('?page_number')

    paginator = Paginator(data, data_per_page)
    page = paginator.page(page_number)
   
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
   
    permissions=data['permissions']
    module_name=data['module_name']

    module_list = ['LEAVE/HOLIDAY_LIST','TIMESHEET']
    if len(module_name) == 1:
        if module_name[0] not in module_list:
            if method == 'POST':
                return 1 ,
            else:
                return 2,Response({
                        'error':{'message':'Key module_name value not valid !',
                        'description':'Enter valid module name',
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)
                
        
    if len(permissions) >= 1:

        first_dic = permissions[0]
        all_keys = {"LEAVE/HOLIDAY","MY_LEAVES","APPLIED/APPROVIED_LEAVES","ADD_ON_LEAVE_REQUEST","LEAVE_MASTER","OFFICE_WORKING_DAYS"}
        
        all_keys_timesheet = {"PEOPLE_TIMESHEET","PEOPLE_TIMESHEET_CALENDER","TODAY_APPROVAL_TIMESHEET","MONTH_APPROVAL_TIMESHEET"}

        if all_keys <= first_dic.keys():
            missing_list = []
            for i in first_dic.keys():
                print(first_dic[i],'iiiiiii')
                if len(first_dic[i]) > 0:
                    access_list = ['CREATE','UPDATE','VIEW','DELETE','APPROVE','REJECT','ACTIVATE/DEACTIVATE']
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
                    return 1 ,

            print('Checking done')
            return 1 ,

        elif all_keys_timesheet <= first_dic.keys():
            missing_list = []
            for i in first_dic.keys():
                print(first_dic[i],'iiiiiii')
                if len(first_dic[i]) > 0:
                    access_list = ["CREATE","UPDATE","VIEW","DELETE","TIMER","LEAVE","COPY","ACCEPT","REJECT","MINE_ONLY","REPORTING_TO_ME","ALL","AUTO_APPROVE"
                ]
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
                    return 1 ,

            print('Checking done')
            return 1 ,
        
        else:
            if module_name == 'TIMESHEET':
                missing_keys = all_keys_timesheet - first_dic.keys()
            else:
                missing_keys = all_keys - first_dic.keys()
            return 2, Response({
                'error':{'message':'Key missing!',
                'missing_key':missing_keys,
                'status_code':status.HTTP_404_NOT_FOUND,
                }},status=status.HTTP_404_NOT_FOUND)
        
        
    else:
        if method == 'POST':
            return 1 ,
        else:
            return 2, Response({
                    'error':{'message':'Permissions key value not found',
                    'description':'Permissions key value is mandatory',
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

            module_list = ['LEAVE/HOLIDAY_LIST','TIMESHEET']
            if request.query_params.get('module') not in module_list:
                return 2, Response({
                    'error':{'message':'Key module_name value not valid !',
                    'description':'Enter valid module name',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
            else:   
                if request.query_params.get('module') == 'LEAVE/HOLIDAY_LIST':
                    print("LEAVE/HOLIDAY_LIST====>")
                    all_menu = ["LEAVE/HOLIDAY","MY_LEAVES","APPLIED/APPROVIED_LEAVES","ADD_ON_LEAVE_REQUEST","LEAVE_MASTER","OFFICE_WORKING_DAYS"]
                elif request.query_params.get('module') == 'TIMESHEET':
                    print("TIMESHEET====>")
                    all_menu = ["PEOPLE_TIMESHEET","PEOPLE_TIMESHEET_CALENDER","TODAY_APPROVAL_TIMESHEET","MONTH_APPROVAL_TIMESHEET"]
                else:
                    return 2, Response({
                        'error':{'message':'Key module_name value not valid !',
                        'description':'Enter valid module name',
                        'status_code':status.HTTP_404_NOT_FOUND,
                        }},status=status.HTTP_404_NOT_FOUND)
                # checking
        
                index_1 = 0 
                for i in user_role_data.module_name:
                
                    if i == request.query_params.get('module'):
                        print( request.query_params.get('module'),'111111main_permission_list==>')
                        index = index_1
                    index_1 = index_1 +1 
                # print(index,'index======>')


                if request.query_params.get('menu') in all_menu:                    
                    permissions = user_role_data.permissions[index][request.query_params.get('menu')]
                    print(permissions,'permission===>',request.query_params.get('method'))
                    print('method===>',request.query_params.get('method'),'-------')
                    
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

            module_list = ['LEAVE/HOLIDAY_LIST','TIMESHEET']
            if data['module'] not in module_list:
                return 2, Response({
                    'error':{'message':'Key module_name value not valid !',
                    'description':'Enter valid module name',
                    'status_code':status.HTTP_404_NOT_FOUND,
                    }},status=status.HTTP_404_NOT_FOUND)
            else:
                if data['module'] == 'LEAVE/HOLIDAY_LIST':
                    all_menu = ["LEAVE/HOLIDAY","MY_LEAVES","APPLIED/APPROVIED_LEAVES","ADD_ON_LEAVE_REQUEST","LEAVE_MASTER","OFFICE_WORKING_DAYS"]
                elif data['module'] == 'TIMESHEET':
                    all_menu = ["PEOPLE_TIMESHEET","PEOPLE_TIMESHEET_CALENDER","TODAY_APPROVAL_TIMESHEET","MONTH_APPROVAL_TIMESHEET"]
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
                    permissions = user_role_data.permissions[index][data['menu']]
                    print(permissions,'permission===>',data['method'])
                    print('method===>',data['method'],'-------')
                    
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
  