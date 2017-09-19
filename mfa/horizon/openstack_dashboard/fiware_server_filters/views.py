# Copyright (C) 2014 Universidad Politecnica de Madrid
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import collections
import json
import logging
import six

from django import http
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.views import generic
from django.views.decorators.csrf import csrf_exempt

from horizon import exceptions

from openstack_dashboard import api
from openstack_dashboard import fiware_api
from openstack_dashboard.local import local_settings
from openstack_dashboard.dashboards.idm import utils as idm_utils


LOG = logging.getLogger('idm_logger')

SHORT_CACHE_TIME = 20 # seconds
FIWARE_PURCHASER_ROLE_ID = getattr(local_settings, "FIWARE_PURCHASER_ROLE_ID")
FIWARE_PROVIDER_ROLE_ID = getattr(local_settings, "FIWARE_PROVIDER_ROLE_ID")

KEYSTONE_OWNER_ROLE = getattr(local_settings, "KEYSTONE_OWNER_ROLE")
KEYSTONE_MEMBER_ROLE = getattr(local_settings, "OPENSTACK_KEYSTONE_DEFAULT_ROLE")

class ComplexAjaxFilter(generic.View):
    """Base view for complex ajax filtering, for example in pagination.
    Supports multiple filters and pagination markers. Uses API filtering
    and pagination in Keystone when possible or implements custom filters.

    The filters should be included as query parameters of the URL.

    .. attribute:: custom_filter_keys

        A dictionary with custom filters that should be handled here and a
        weight to set order of filtering (lower numbers go first). The rest 
        of the filters will be forwarded to the api call. For each custom
        key a function with name [custom_key_name_filter] should be 
        implemented. This function gets executed AFTER the api call.
        Default is an empty dict (``{}``).
    """
    http_method_names = ['get']
    custom_filter_keys = {}
    page_size = getattr(local_settings, "PAGE_SIZE")
    paginate = True
    item_detail_url = None
    url_id_key = None

    def get(self, request, *args, **kwargs):
        # NOTE(garcianavalon) replace with JsonResponse when 
        # Horizon uses Django 1.7+
        filters = request.GET.items()
        try:
            response_data = self.load_data(request, filters=filters)
            return http.HttpResponse(
                json.dumps(response_data), 
                content_type="application/json")
            
        except Exception as exc:
            LOG.error(str(exc))
            exceptions.handle(request, 'Unable to filter.')

    def api_call(self, request, filters):
        """Override to add the corresponding api call, for example:
            api.keystone.users_list(request, filters=filters)
        WARNING: the return object must be json-serializable
        """
        raise NotImplementedError

    def _separate_filters(self, filters):
        """Returns a dictionary with all the custom
        filters present in the received filters dictionary and
        a dictionary with all the non-custom filters.
        """
        custom_filters = {}
        api_filters = {}
        for key, value in filters:
            if key in self.custom_filter_keys.keys():
                custom_filters[key] = value
            else:
                api_filters[key] = value

        ordered_custom_filters = collections.OrderedDict(
            sorted(custom_filters.items(), key=lambda t: self.custom_filter_keys[t[0]]))

        return ordered_custom_filters, api_filters

    def load_data(self, request, filters):
        custom_filters, api_filters = self._separate_filters(filters)

        # NOTE(garcianavalon) until we can use API pagination
        page_number = api_filters.pop('page', None)

        data = self.api_call(request, filters=api_filters)

        if self.item_detail_url and self.url_id_key:
            for item in data:
                item['detail_url'] = reverse(
                    self.item_detail_url, kwargs={self.url_id_key:item['id']})

        for key, value in six.iteritems(custom_filters):
            data = getattr(self, key + '_filter')(request, data, value)

        if self.paginate and page_number:
            # Always after all the filters are done
            data = self.pagination(data, page_number)
        else:
            data = {
                'items':data,
            }

        return data

    def pagination(self, data, page_number):
        data = self._sorting_method(data)
        return {
            'items':idm_utils.paginate_list(data, int(page_number), self.page_size),
            'pages':idm_utils.total_pages(data, self.page_size),
        }

    def _sorting_method(self, data):
        return sorted(data, key=lambda x: x['name'].lower())


class OrganizationsComplexFilter(ComplexAjaxFilter):
    custom_filter_keys = {
        'application_id': 5,
        'organization_role':6,
    }
    item_detail_url = 'horizon:idm:organizations:detail'
    url_id_key = 'organization_id'

    def application_id_filter(self, request, json_orgs, application_id):
        role_assignments = fiware_api.keystone.organization_role_assignments(
            request, application=application_id)

        authorized_organizations = set([a.organization_id for a in role_assignments])
        organizations = [org for org in json_orgs if org['id']
                 in authorized_organizations]

        return organizations

    def organization_role_filter(self, request, json_orgs, role_name):
        my_organizations = fiware_api.keystone.project_list(
            request, user=request.user.id)
        my_organizations = [org.id for org in my_organizations]
        # NOTE(garcianavalon) the organizations the user is owner(admin)
        # are already in the request object by the middleware
        owner_organizations = [org.id for org in request.organizations]

        if role_name == 'OTHER':
            json_orgs = [org for org in json_orgs if not org['id'] in my_organizations]

        elif role_name == KEYSTONE_MEMBER_ROLE:
            json_orgs = [org for org in json_orgs if org['id'] in my_organizations
                         and not org['id'] in owner_organizations]

        elif role_name == KEYSTONE_OWNER_ROLE:
            json_orgs = [org for org in json_orgs if org['id'] in owner_organizations]

        else:
            # TODO(garcianavalon) support for generic roles if needed
            pass

        return json_orgs

    def api_call(self, request, filters):
        user_id = filters.pop('user_id', None)
        organizations = idm_utils.filter_default(
            fiware_api.keystone.project_list(request, filters=filters, user=user_id))

        attrs = [
            'id',
            'name',
            'img_small',
            'description',
        ]

        # add MEDIA_URL to avatar paths or the default avatar
        json_orgs = []
        for org in organizations:
            json_org = idm_utils.obj_to_jsonable_dict(org, attrs) 
            json_org['img_small'] = idm_utils.get_avatar(json_org, 
                'img_small', idm_utils.DEFAULT_ORG_SMALL_AVATAR)
            json_orgs.append(json_org)
            
        return json_orgs

    def load_data(self, request, filters):
        data = super(OrganizationsComplexFilter, self).load_data(request, filters)

        owner_organizations = [org.id for org in request.organizations]
        for org in data['items']:
            if org['id'] not in owner_organizations:
                continue
            org['switch'] = idm_utils.get_switch_url(org, check_switchable=False)
        
        return data 

class UsersComplexFilter(ComplexAjaxFilter):
    custom_filter_keys = {
        'application_id': 5,
        'organization_id':6,
    }
    item_detail_url = 'horizon:idm:users:detail'
    url_id_key = 'user_id'


    def organization_id_filter(self, request, json_users, organization_id):
        project_users_roles = api.keystone.get_project_users_roles(
            request, project=organization_id)

        users = [user for user in json_users if user['id'] in project_users_roles]

        return users

    def application_id_filter(self, request, json_users, application_id):
        role_assignments = fiware_api.keystone.user_role_assignments(
            request, application=application_id)
        
        authorized_users = []
        added_users = []
        for assignment in role_assignments:
            if assignment.user_id in added_users:
                # NOTE(garcianavalon) we can't use a set because
                # user is a dictionary for json-paring later
                continue
            user = next(
                (user for user in json_users if user['id'] == assignment.user_id), None)
            if user and user['default_project_id'] == assignment.organization_id:
                authorized_users.append(user)
                added_users.append(user['id'])

        return authorized_users

    def api_call(self, request, filters):
        if 'name__startswith' in filters:
            # NOTE(garcianavalon) we wan't to filter by username, not name
            filters['username__startswith'] = filters.pop('name__startswith')

        filters.update({'enabled':True})
        users = fiware_api.keystone.user_list(request, filters=filters)

        attrs = [
            'id',
            'username',
            'default_project_id',
            'img_small',
        ]

        # add MEDIA_URL to avatar paths or the default avatar
        json_users = []
        for user in users:
            # Never show users with out username
            if not getattr(user, 'username', None):
                continue

            json_user = idm_utils.obj_to_jsonable_dict(user, attrs)
            json_user['img_small'] = idm_utils.get_avatar(
                user, 'img_small', idm_utils.DEFAULT_USER_SMALL_AVATAR)

            # Consistency with other elements
            json_user['name'] = json_user.pop('username')

            json_users.append(json_user)

        return json_users

class ApplicationsComplexFilter(ComplexAjaxFilter):
    custom_filter_keys = {
        'organization_id': 5,
        'application_role': 6,
        'user_id': 4,
    }
    item_detail_url = 'horizon:idm:myApplications:detail'
    url_id_key = 'application_id'

    def user_id_filter(self, request, json_apps, user_id):
        role_assignments = fiware_api.keystone.user_role_assignments(
            request, user=user_id)

        apps_with_roles = [a.application_id for a in role_assignments]       
        
        json_apps = [app for app in json_apps if app['id'] in apps_with_roles]

        return json_apps

    def organization_id_filter(self, request, json_apps, organization_id):
        role_assignments = fiware_api.keystone.organization_role_assignments(
            request, organization=organization_id)
        apps_with_roles = [a.application_id for a in role_assignments]

        applications = [app for app in json_apps if app['id'] in apps_with_roles]

        return applications

    def application_role_filter(self, request, json_apps, role_id):
        if request.organization.id == request.user.default_project_id:
            role_assignments = fiware_api.keystone.user_role_assignments(
                               request, user=request.user.id)
        else:
            role_assignments = fiware_api.keystone.organization_role_assignments(
                               request, organization=request.organization.id)

        if role_id == 'OTHER':
            # Special case, not provider or purchaser.
            not_roles = [FIWARE_PURCHASER_ROLE_ID, FIWARE_PROVIDER_ROLE_ID]
            apps_with_roles = [a.application_id for a in role_assignments
                               if a.role_id not in not_roles] 
        else:
            apps_with_roles = [a.application_id for a in role_assignments
                               if a.role_id == role_id]       
        
        json_apps = [app for app in json_apps if app['id'] in apps_with_roles]

        return json_apps

    def api_call(self, request, filters):
        applications = idm_utils.filter_default(fiware_api.keystone.application_list(request))
            # request, filters=filters)) TODO(garcianavalon) filter support!

        attrs = [
            'id',
            'name',
            'img_small',
            'url',
        ]

        # add MEDIA_URL to avatar paths or the default avatar
        json_apps = []
        for app in applications:
            json_app = idm_utils.obj_to_jsonable_dict(app, attrs)
            json_app['img_small'] = idm_utils.get_avatar(
                json_app, 'img_small', idm_utils.DEFAULT_APP_SMALL_AVATAR)
            json_apps.append(json_app)

        return json_apps
