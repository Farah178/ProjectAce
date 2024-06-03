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