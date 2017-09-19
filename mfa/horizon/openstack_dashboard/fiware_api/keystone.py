# Copyright (C) 2014 Universidad Politecnica de Madrid
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import json
import logging
import requests
import uuid

from django.conf import settings
from django.core import exceptions as django_exceptions
from django.core.cache import cache

from openstack_dashboard import api
from openstack_dashboard.local import local_settings

from horizon import exceptions
from horizon.utils import functions as utils

from keystoneclient import exceptions as ks_exceptions
from keystoneclient import session
from keystoneclient.auth.identity import v3
from keystoneclient.v3 import client


LOG = logging.getLogger('idm_logger')
# NOTE(garcianavalon) time in seconds to cache the default roles
# and other objects
DEFAULT_OBJECTS_CACHE_TIME = 60 * 15
INTERNAL_CLIENT_CACHE_TIME = 60 * 60
CACHE_CLIENT = "_internal_keystoneclient_token"
CACHE_TOKEN = "_internal_keystoneclient"

# NOTE(garcianavalon) prevent MemCache Warnings because we use
# LocMemCache
import warnings
from django.core.cache import CacheKeyWarning
warnings.simplefilter("ignore", CacheKeyWarning)

def internal_keystoneclient(request):
    """Creates a connection with keystone using the IdM account.

    The client is cached so that subsequent API calls don't have
    to be re-authenticated.
    """
    token = cache.get(CACHE_CLIENT, None)
    old_client = cache.get(CACHE_TOKEN, None)
    if not token:
        #LOG.debug('There is no token cached -> New Password Session')
        idm_password_session = _password_session(request)
        keystoneclient = client.Client(session=idm_password_session)
        cache.set(CACHE_CLIENT, keystoneclient.session.get_token(), INTERNAL_CLIENT_CACHE_TIME)
        cache.set(CACHE_TOKEN, keystoneclient, INTERNAL_CLIENT_CACHE_TIME)
        #LOG.debug('Saved token: %s',keystoneclient.session.get_token())
    else:
        #LOG.debug('There is a cached token! (%s)',token)
        old_client._auth_token = token
        keystoneclient = old_client

    #LOG.debug('Using token: %s',keystoneclient.session.get_token())
    return keystoneclient

def _password_session(request):
    # TODO(garcianavalon) better domain usage
    domain = 'default'
    endpoint = getattr(settings, 'OPENSTACK_KEYSTONE_URL')
    insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
    verify = getattr(settings, 'OPENSTACK_SSL_CACERT', True)

    if insecure:
        verify = False

    credentials = getattr(settings, 'IDM_USER_CREDENTIALS')

    LOG.debug(
        ('Creating a new internal keystoneclient '
         'connection to %s.'),
        endpoint)
    auth = v3.Password(
        username=credentials['username'],
        password=credentials['password'],
        project_name=credentials['project'],
        user_domain_id=domain,
        project_domain_id=domain,
        auth_url=endpoint)

    return session.Session(auth=auth, verify=verify)

# PEP PROXY
def register_pep_proxy(request, application_id, password=None):
    pep_proxies_group = getattr(settings, 'PEP_PROXIES_GROUP', None)
    if not pep_proxies_group:
        LOG.error('PEP_PROXIES_GROUP is not set in local_settings.py')
        return

    pep_proxies_role = getattr(settings, 'PEP_PROXIES_ROLE', None)
    if not pep_proxies_role:
        LOG.error('PEP_PROXIES_ROLE is not set in local_settings.py')
        return

    # create user with random password and unique name
    username = 'pep_proxy_' + uuid.uuid4().hex
    if not password:
        password = uuid.uuid4().hex
    keystone = internal_keystoneclient(request)
    # TODO(garcianavalon) better domain usage
    domain = 'default'
    pep = keystone.users.create(username, password=password, domain=domain)

    # add it to the pep proxy group
    try:
        pep_group = keystone.groups.find(name=pep_proxies_group)
    except ks_exceptions.NotFound:
        LOG.debug('Creating PEP Proxies group in Keystone')
        pep_group = keystone.groups.create(name=pep_proxies_group, domain=domain)
    
    # asign a role in the domain to the group
    try:
        pep_role = keystone.roles.find(name=pep_proxies_role)
    except ks_exceptions.NotFound:
        LOG.debug('Creating PEP Proxies role in Keystone')
        pep_role = keystone.roles.create(name=pep_proxies_role, domain=domain)
        keystone.roles.grant(pep_role, group=pep_group, domain=domain)

    keystone.users.add_to_group(user=pep, group=pep_group)

    # done!
    return pep

def reset_pep_proxy(request, pep_proxy_name, password=None):
    if not password:
        password = uuid.uuid4().hex
    keystone = internal_keystoneclient(request)
    pep = keystone.users.find(name=pep_proxy_name)
    return keystone.users.update(pep, password=password)

def delete_pep_proxy(request, pep_proxy_name):
    keystone = internal_keystoneclient(request)
    pep = keystone.users.find(name=pep_proxy_name)
    return keystone.users.delete(pep)

# USER REGISTRATION
def _find_user(keystone, email=None, username=None):
    if email:
        user = keystone.users.find(name=email)
        return user
    elif username:
        user_list = keystone.users.list()
        for user in user_list:
            if hasattr(user, 'username') and user.username == username:
                return user
        # consistent behaviour with the keystoneclient api
        msg = "No user matching email=%s." % email
        raise ks_exceptions.NotFound(404, msg)

def get_trial_role_assignments(request, domain='default', use_idm_account=False):
    trial_role = get_trial_role(request, use_idm_account=False)
    if trial_role:
        manager = internal_keystoneclient(request).role_assignments
        return manager.list(role=trial_role.id, domain=domain)
    else:
        return []

def register_user(request, name, username, password):
    keystone = internal_keystoneclient(request)
    #domain_name = getattr(settings, 'OPENSTACK_KEYSTONE_DEFAULT_DOMAIN', 'Default')
    #default_domain = keystone.domains.find(name=domain_name)
    # TODO(garcianavalon) better domain usage
    default_domain = 'default'
    # if not (check_user(name) or check_email(email)):
    new_user = keystone.user_registration.users.register_user(
        name,
        domain=default_domain,
        password=password,
        username=username)
    return new_user

def activate_user(request, user, activation_key):
    keystone = internal_keystoneclient(request)
    user = keystone.user_registration.users.activate_user(user, activation_key)
    return user

def change_password(request, user_email, new_password):
    keystone = internal_keystoneclient(request)
    user = _find_user(keystone, email=user_email)
    user = keystone.users.update(user, password=new_password, enabled=True)
    return user

def check_username(request, username):
    keystone = internal_keystoneclient(request)
    user = _find_user(keystone, username=username)
    return user

def check_email(request, email):
    keystone = internal_keystoneclient(request)
    user = _find_user(keystone, email=email)
    return user

def get_reset_token(request, user):
    keystone = internal_keystoneclient(request)
    token = keystone.user_registration.token.get_reset_token(user)
    return token

def new_activation_key(request, user):
    keystone = internal_keystoneclient(request)
    activation_key = keystone.user_registration.activation_key.new_activation_key(user)
    return activation_key

def reset_password(request, user, token, new_password):
    keystone = internal_keystoneclient(request)

    user = keystone.user_registration.users.reset_password(user, token, new_password)
    return user

def user_delete(request, user):
    keystone = internal_keystoneclient(request)
    keystone.users.delete(user)

# validate token
def validate_keystone_token(request, token):
    keystone = internal_keystoneclient(request)
    return keystone.tokens.validate(token, include_catalog=False)


# ROLES
def role_get(request, role_id):
    manager = internal_keystoneclient(request).fiware_roles.roles
    return manager.get(role_id)

def role_list(request, user=None, organization=None, application=None):
    manager = internal_keystoneclient(request).fiware_roles.roles
    return manager.list(user=user,
                        organization=organization,
                        application_id=application)

def role_create(request, name, is_internal=False, application=None, **kwargs):
    manager = internal_keystoneclient(request).fiware_roles.roles
    return manager.create(name=name,
                          is_internal=is_internal,
                          application=application,
                          **kwargs)

def role_update(request, role, name=None, is_internal=False, 
                application=None, **kwargs):
    manager = internal_keystoneclient(request).fiware_roles.roles
    return manager.update(role,
                          name=name,
                          is_internal=is_internal,
                          application=application,
                          **kwargs)

def role_delete(request, role_id):
    manager = internal_keystoneclient(request).fiware_roles.roles
    return manager.delete(role_id)


# ROLE-USERS
def add_role_to_user(request, role, user, organization, 
                     application, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).fiware_roles.roles
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).fiware_roles.roles
    return manager.add_to_user(role, user, organization, application)

def remove_role_from_user(request, role, user, organization, application,
                          use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).fiware_roles.roles
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).fiware_roles.roles
    return manager.remove_from_user(role, user, organization, application)

def user_role_assignments(request, user=None, organization=None,
                          application=None, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request)
    else:
        manager = api.keystone.keystoneclient(request, admin=True)
    manager = manager.fiware_roles.role_assignments
    return manager.list_user_role_assignments(user=user,
                                              organization=organization,
                                              application=application)
# ROLE-ORGANIZATIONS
def add_role_to_organization(request, role, organization, 
                             application, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).fiware_roles.roles
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).fiware_roles.roles
    return manager.add_to_organization(role, organization, application)

def remove_role_from_organization(request, role, organization, application,
                                  use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).fiware_roles.roles
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).fiware_roles.roles
    return manager.remove_from_organization(role, organization, application)

def organization_role_assignments(request, organization=None,
                                  application=None, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request)
    else:
        manager = api.keystone.keystoneclient(request, admin=True)   
    manager = manager.fiware_roles.role_assignments
    return manager.list_organization_role_assignments(
        organization=organization, application=application)

# ALLOWED ACTIONS
def list_user_allowed_roles_to_assign(request, user, organization):
    manager = api.keystone.keystoneclient(
        request, admin=True).fiware_roles.allowed
    return manager.list_user_allowed_roles_to_assign(user, organization)

def list_organization_allowed_roles_to_assign(request, organization):
    manager = api.keystone.keystoneclient(
        request, admin=True).fiware_roles.allowed
    return manager.list_organization_allowed_roles_to_assign(organization)

def list_user_allowed_applications_to_manage(request, user, organization):
    manager = api.keystone.keystoneclient(
        request, admin=True).fiware_roles.allowed
    return manager.list_user_allowed_applications_to_manage(user, organization)

def list_organization_allowed_applications_to_manage(request, organization):
    manager = api.keystone.keystoneclient(
        request, admin=True).fiware_roles.allowed
    return manager.list_organization_allowed_applications_to_manage(organization)

def list_user_allowed_applications_to_manage_roles(request, user, organization):
    manager = api.keystone.keystoneclient(
        request, admin=True).fiware_roles.allowed
    return manager.list_user_allowed_applications_to_manage_roles(
        user, organization)

def list_organization_allowed_applications_to_manage_roles(request, organization):
    manager = api.keystone.keystoneclient(
        request, admin=True).fiware_roles.allowed
    return manager.list_organization_allowed_applications_to_manage_roles(
        organization)

# PERMISSIONS
def permission_get(request, permission_id):
    manager = internal_keystoneclient(request).fiware_roles.permissions
    return manager.get(permission_id)

def permission_list(request, role=None, application=None):
    manager = internal_keystoneclient(request).fiware_roles.permissions
    return manager.list(role=role,
                        application_id=application)

def permission_create(request, name, is_internal=False, application=None, **kwargs):
    manager = internal_keystoneclient(request).fiware_roles.permissions
    return manager.create(name=name,
                          is_internal=is_internal,
                          application=application,
                          **kwargs)

def permission_update(request, permission, name=None, is_internal=False, 
                      application=None, **kwargs):
    manager = internal_keystoneclient(request).fiware_roles.permissions
    return manager.update(permission,
                          name=name,
                          is_internal=is_internal,
                          application_=application,
                          **kwargs)

def permission_delete(request, permission_id):
    manager = internal_keystoneclient(request).fiware_roles.permissions
    return manager.delete(permission_id)

def add_permission_to_role(request, permission, role):
    manager = internal_keystoneclient(request).fiware_roles.permissions
    return manager.add_to_role(permission=permission, role=role)

def remove_permission_from_role(request, permission, role):
    manager = internal_keystoneclient(request).fiware_roles.permissions
    return manager.remove_from_role(permission=permission, role=role)

# APPLICATIONS/CONSUMERS
def application_create(request, name, redirect_uris, scopes=['all_info'],
                       client_type='confidential', description=None,
                       grant_type='authorization_code', **kwargs):
    """ Registers a new consumer in the Keystone OAuth2 extension.

    In FIWARE applications is the name OAuth2 consumers/clients receive.
    """
    manager = api.keystone.keystoneclient(request, admin=True).oauth2.consumers
    return manager.create(name=name,
                          redirect_uris=redirect_uris,
                          description=description,
                          scopes=scopes,
                          client_type=client_type,
                          grant_type=grant_type,
                          **kwargs)

def application_list(request, user=None):
    manager = internal_keystoneclient(request).oauth2.consumers
    return manager.list(user=user)

def application_get(request, application_id, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).oauth2.consumers
    else:
        manager = api.keystone.keystoneclient(request, admin=True).oauth2.consumers
    return manager.get(application_id)

def application_update(request, consumer_id, name=None, description=None, client_type=None, 
                       redirect_uris=None, grant_type=None, scopes=None, **kwargs):
    manager = internal_keystoneclient(request).oauth2.consumers
    return manager.update(consumer=consumer_id,
                          name=name,
                          description=description,
                          client_type=client_type,
                          redirect_uris=redirect_uris,
                          grant_type=grant_type,
                          scopes=scopes,
                          **kwargs)

def application_delete(request, application_id, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request)
    else:
        manager = api.keystone.keystoneclient(request, admin=True)

    return manager.oauth2.consumers.delete(application_id)


# OAUTH2 FLOW
def get_user_access_tokens(request, user):
    """Gets all authorized access_tokens for the user"""
    manager = internal_keystoneclient(request).oauth2.access_tokens

    return manager.list_for_user(user=user)

def request_authorization_for_application(request, application, redirect_uri,
                                          response_type, scope=['all_info'], state=None):
    """ Sends the consumer/client credentials to the authorization server to ask
    a resource owner for authorization in a certain scope.

    :returns: a dict with all the data response from the provider, use it to populate
        a nice form for the user, for example.
    """
    LOG.debug('Requesting authorization for application: {0} with redirect_uri: {1} \
        and scope: {2} by user {3}'.format(application, redirect_uri, scope, request.user))
    manager = api.keystone.keystoneclient(request, admin=True).oauth2.authorization_codes
    response_dict = manager.request_authorization(consumer=application,
                                                  redirect_uri=redirect_uri,
                                                  response_type=response_type,
                                                  scope=scope,
                                                  state=state)
    return  response_dict

def authorize_application(request, application, scopes=None, redirect=False):
    """ Give authorization from a resource owner to the consumer/client on the
    requested scopes.

    Example use case: when the user is redirected from the application website to
    us, the provider/resource owner we present a nice form. If the user accepts, we
    delegate to our Keystone backend, where the client credentials will be checked an
    an authorization_code returned if everything is correct.

    :returns: an authorization_code object, following the same pattern as other
        keystoneclient objects
    """
    if not scopes:
        scopes = ['all_info']

    LOG.debug('Authorizing application: %s by user: %s', application, request.user)
    manager = api.keystone.keystoneclient(request, admin=True).oauth2.authorization_codes
    authorization_code = manager.authorize(consumer=application,
                                           scopes=scopes,
                                           redirect=redirect)
    return authorization_code

def obtain_access_token(request, consumer_id, consumer_secret, code,
                        redirect_uri):
    """ Exchange the authorization_code for an access_token.

    This token can be later exchanged for a keystone scoped token using the oauth2
    auth method. See the Keystone OAuth2 Extension documentation for more information
    about the auth plugin.

    :returns: an access_token object
    """
    # NOTE(garcianavalon) right now this method has no use because is a wrapper for a
    # method intented to be use by the client/consumer. For the IdM is much more 
    # convenient to simply forward the request, see forward_access_token_request method
    LOG.debug('Exchanging code: {0} by application: {1}'.format(code, consumer_id))
    manager = internal_keystoneclient(request).oauth2.access_tokens
    access_token = manager.create(consumer_id=consumer_id,
                                  consumer_secret=consumer_secret,
                                  authorization_code=code,
                                  redirect_uri=redirect_uri)
    return access_token

def forward_access_token_request(request):
    """ Forwards the request to the keystone backend."""
    # TODO(garcianavalon) figure out if this method belongs to keystone client or if
    # there is a better way to do it/structure this
    auth = request.META.get('HTTP_AUTHORIZATION', None)
    if not auth:
        raise django_exceptions.PermissionDenied()

    headers = {
        'Authorization': auth,
        'Content-Type': request.META['CONTENT_TYPE'],
    }
    body = request.body
    keystone_url = getattr(settings, 'OPENSTACK_KEYSTONE_URL') + '/OS-OAUTH2/access_token'
    LOG.debug('API_KEYSTONE: POST to %s with body %s and headers %s', 
              keystone_url, body, headers)
    response = requests.post(keystone_url, data=body, headers=headers)
    return response

def forward_implicit_grant_authorization_request(request, application_id, scopes=None):
    """ Forwards the request to the keystone backend. The implict grant authorization
    returns an access token instead of an authorization code.
    """
    # TODO(garcianavalon) figure out if this method belongs to keystone client or if
    # there is a better way to do it/structure this
    if not scopes:
        scopes = ['all_info']
    headers = {
        'Content-Type': 'application/json',
    }
    body = {
        'user_auth': {
            'client_id':application_id,
            'scopes':scopes,
            'user_id': request.user.id,
        }
    }
    keystone_url = getattr(settings, 'OPENSTACK_KEYSTONE_URL') + '/OS-OAUTH2/authorize'
    LOG.debug('API_KEYSTONE: POST to %s with body %s and headers %s', 
              keystone_url, body, headers)

    response = requests.post(keystone_url, data=json.dumps(body), headers=headers, allow_redirects=False)
    return response

# FIWARE-IdM API CALLS
def forward_validate_token_request(request):
    """ Forwards the request to the keystone backend."""
    # TODO(garcianavalon) figure out if this method belongs to keystone client or if
    # there is a better way to do it/structure this
    keystone_url = getattr(settings, 'OPENSTACK_KEYSTONE_URL')
    endpoint = '/access-tokens/{0}'.format(request.GET.get('access_token'))
    url = keystone_url + endpoint
    LOG.debug('API_KEYSTONE: GET to {0}'.format(url))
    response = requests.get(url)
    return response

# TWO FACTOR AUTHENTICATION
def two_factor_is_enabled(request, user):
    manager = internal_keystoneclient(request).two_factor.keys
    return manager.check_activated_two_factor(user_id=user.id)

def two_factor_new_key(request, user, security_question=None, security_answer=None):
    manager = internal_keystoneclient(request).two_factor.keys
    res = manager.generate_new_key(user, security_question, security_answer)
    return (res.two_factor_key, res.uri)

def two_factor_disable(request, user):
    manager = internal_keystoneclient(request).two_factor.keys
    return manager.deactivate_two_factor(user)

def two_factor_get_security_question(request, user):
    manager = internal_keystoneclient(request).two_factor.keys
    data = manager.get_two_factor_data(user)
    return data.security_question

def two_factor_check_security_question(request, user, security_answer):
    manager = internal_keystoneclient(request).two_factor.keys
    try:
        manager.check_security_question(user, security_answer)
        return True
    except ks_exceptions.HttpError:
        return False

def two_factor_forget_all_devices(request, user):
    manager = internal_keystoneclient(request).two_factor.keys
    return manager.delete_all_devices(user)

# CALLS FORBIDDEN FOR THE USER THAT NEED TO USE THE IDM ACCOUNT
# USERS
def user_get(request, user_id):
    manager = internal_keystoneclient(request).users
    return manager.get(user_id)

def user_list(request, project=None, domain=None, group=None, filters=None):
    manager = internal_keystoneclient(request).users

    kwargs = {
        "project": project,
        "domain": domain,
        "group": group
    }
    if filters is not None:
        kwargs.update(filters)
    return manager.list(**kwargs)

def user_update(request, user, use_idm_account=False, **data):
    if use_idm_account:
        manager = internal_keystoneclient(request).users
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).users

    if not data['password']:
        data.pop('password')
    user = manager.update(user, **data)
    if data.get('password') and user.id == request.user.id:
        return utils.logout_with_message(
            request,
            "Password changed. Please log in again to continue."
        )

def keystone_role_list(request):
    manager = internal_keystoneclient(request).roles
    return manager.list()
    
# PROJECTS
def project_get(request, project_id):
    manager = internal_keystoneclient(request).projects
    return manager.get(project_id)

def project_list(request, domain=None, user=None, filters=None):
    manager = internal_keystoneclient(request).projects
    kwargs = {
        "domain": domain,
        "user": user
    }
    if filters is not None:
        kwargs.update(filters)
    return manager.list(**kwargs)

def project_create(request, name, description=None, enabled=None,
                   domain=None, **kwargs):
    manager = internal_keystoneclient(request).projects
    return manager.create(name, domain,
                          description=description,
                          enabled=enabled, **kwargs)

def project_update(request, project, name=None, description=None,
                  enabled=None, domain=None, **kwargs):
    manager = internal_keystoneclient(request).projects
    return manager.update(project, name=name, description=description,
                          enabled=enabled, domain=domain, **kwargs)

def project_delete(request, project):
    manager = internal_keystoneclient(request).projects
    return manager.delete(project)

# ROLES
def add_domain_user_role(request, user, role, domain):
    manager = internal_keystoneclient(request).roles
    return manager.grant(role, user=user, domain=domain)

def remove_domain_user_role(request, user, role, domain):
    manager = internal_keystoneclient(request).roles
    return manager.revoke(role, user=user, domain=domain)

def role_assignments_list(request, project=None, user=None, role=None,
                          group=None, domain=None, effective=False):
    manager = internal_keystoneclient(request).role_assignments
    return manager.list(project=project, user=user, role=role, group=group,
                        domain=domain, effective=effective)


# REGIONS AND ENDPOINT GROUPS
def region_list(request, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).regions
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).regions
    return manager.list()

def endpoint_group_list(request, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).endpoint_groups
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).endpoint_groups
    return manager.list()

def add_endpoint_group_to_project(request, project, endpoint_group, 
                                  use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).endpoint_groups
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).endpoint_groups
    return manager.add_endpoint_group_to_project(
        project=project,
        endpoint_group=endpoint_group)

def delete_endpoint_group_from_project(request, project, endpoint_group, 
                                       use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).endpoint_groups
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).endpoint_groups
    return manager.delete_endpoint_group_from_project(
        project=project,
        endpoint_group=endpoint_group)

def check_endpoint_group_in_project(request, project, endpoint_group, 
                                    use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).endpoint_groups
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).endpoint_groups
    return manager.check_endpoint_group_in_project(
        project=project,
        endpoint_group=endpoint_group)

def list_endpoint_groups_for_project(request, project, use_idm_account=False):
    if use_idm_account:
        manager = internal_keystoneclient(request).endpoint_groups
    else:
        manager = api.keystone.keystoneclient(
            request, admin=True).endpoint_groups
    return manager.list_endpoint_groups_for_project(
        project=project)

# USER CATEGORIES
def update_to_trial(request, user, duration=None):
    trial_role = get_trial_role(request, use_idm_account=False)
    date = str(datetime.date.today())
    keystone = internal_keystoneclient(request)
    if not duration:
        duration = settings.FIWARE_DEFAULT_DURATION[trial_role.name]
    keystone.users.update(user, trial_started_at=date, trial_duration=duration)
    add_domain_user_role(
        request,
        user=user,
        role=trial_role.id,
        domain='default')

def update_to_community(request, user, duration=None):
    community_role = get_community_role(request, use_idm_account=False)
    date = str(datetime.date.today())
    keystone = internal_keystoneclient(request)
    if not duration:
        duration = settings.FIWARE_DEFAULT_DURATION[community_role.name]
    keystone.users.update(user, community_started_at=date, community_duration=duration)
    add_domain_user_role(
        request,
        user=user,
        role=community_role.id,
        domain='default')

def update_to_basic(request, user):
    basic_role = get_basic_role(request, use_idm_account=False)
    add_domain_user_role(
        request,
        user=user,
        role=basic_role.id,
        domain='default')

# SPECIAL ROLES
# TODO(garcianavalon) refactorize for better reuse
class PickleObject():
    """Extremely simple class that holds the very little information we need
    to cache. Keystoneclient resource objects are not pickable.
    """
    def __init__(self, **kwds):
        self.__dict__.update(kwds)

def _get_element_and_cache(request, role, function):
    if not cache.get(role):
        try:
            role = function(request, role)
            pickle_role = PickleObject(name=role.name, id=role.id)
            cache.set(role, pickle_role, DEFAULT_OBJECTS_CACHE_TIME)
        except Exception as e:
            exceptions.handle(request)
    return cache.get(role)

def get_owner_role(request, use_idm_account=False):
    owner = getattr(local_settings, "KEYSTONE_OWNER_ROLE")
    return _get_element_and_cache(
        request, owner, lambda req, n: internal_keystoneclient(req).roles.find(name=n))

def get_member_role(request, use_idm_account=False):
    member = getattr(local_settings, "OPENSTACK_KEYSTONE_DEFAULT_ROLE")
    return _get_element_and_cache(
        request, member, lambda req, n: internal_keystoneclient(req).roles.find(name=n))

def get_trial_role(request, use_idm_account=False):
    trial = getattr(local_settings, "KEYSTONE_TRIAL_ROLE")
    return _get_element_and_cache(
        request, trial, lambda req, n: internal_keystoneclient(req).roles.find(name=n))

def get_basic_role(request, use_idm_account=False):
    basic = getattr(local_settings, "KEYSTONE_BASIC_ROLE")
    return _get_element_and_cache(
        request, basic, lambda req, n: internal_keystoneclient(req).roles.find(name=n))

def get_community_role(request, use_idm_account=False):
    community = getattr(local_settings, "KEYSTONE_COMMUNITY_ROLE")
    return _get_element_and_cache(
        request, community, lambda req, n: internal_keystoneclient(req).roles.find(name=n))

def get_provider_role(request, use_idm_account=False):
    provider = getattr(local_settings, "FIWARE_PROVIDER_ROLE_ID")
    return _get_element_and_cache(
        request, provider, lambda req, role_id: internal_keystoneclient(req).fiware_roles.roles.get(role_id))

def get_purchaser_role(request, use_idm_account=False):
    purchaser = getattr(local_settings, "FIWARE_PURCHASER_ROLE_ID")
    return _get_element_and_cache(
        request, purchaser, lambda req, role_id: internal_keystoneclient(req).fiware_roles.roles.get(role_id))


def get_default_cloud_role(request, cloud_app_id, use_idm_account=False):
    """Gets the default_cloud role object from Keystone and caches it.

    Since this is configured in settings and should not change from request
    to request. Supports lookup by name or id.
    """
    default_cloud = getattr(local_settings, "FIWARE_DEFAULT_CLOUD_ROLE_ID")
    return _get_element_and_cache(
        request, default_cloud, lambda req, role_id: internal_keystoneclient(req).fiware_roles.roles.get(role_id))


def get_idm_admin_app(request):
    idm_admin = getattr(local_settings, "FIWARE_IDM_ADMIN_APP", None)
    if idm_admin and cache.get('idm_admin') is None:
        try:
            apps = internal_keystoneclient(request).oauth2.consumers.list()
        except Exception:
            apps = []
            exceptions.handle(request)
        for app in apps:
            if app.id == idm_admin or app.name == idm_admin:
                pickle_app = PickleObject(name=app.name, id=app.id)
                cache.set('idm_admin', pickle_app, DEFAULT_OBJECTS_CACHE_TIME)
                break
    return cache.get('idm_admin')

def get_fiware_cloud_app(request, use_idm_account=False):
    cloud_app = getattr(local_settings, "FIWARE_CLOUD_APP", None)
    if cloud_app and cache.get('cloud_app') is None:
        try:
            if use_idm_account:
                manager = internal_keystoneclient(request)
            else:
                manager = api.keystone.keystoneclient(request, admin=True)
            apps = manager.oauth2.consumers.list()
        except Exception:
            apps = []
            exceptions.handle(request)
        for app in apps:
            if app.id == cloud_app or app.name == cloud_app:
                pickle_app = PickleObject(name=app.name, id=app.id)
                cache.set('cloud_app', pickle_app, DEFAULT_OBJECTS_CACHE_TIME)
                break
    return cache.get('cloud_app')

def get_fiware_default_app(request, app_name, use_idm_account=False):
    if cache.get(app_name) is None:
        try:
            if use_idm_account:
                manager = internal_keystoneclient(request)
            else:
                manager = api.keystone.keystoneclient(request, admin=True)
            apps = manager.oauth2.consumers.list()
        except Exception:
            apps = []
            exceptions.handle(request)
        for app in apps:
            if app.name == app_name:
                pickle_app = PickleObject(name=app.name, id=app.id)
                cache.set(app_name, pickle_app, DEFAULT_OBJECTS_CACHE_TIME)
                break
    return cache.get(app_name)

def get_fiware_default_apps(request):
    default_apps_names = getattr(local_settings, "FIWARE_DEFAULT_APPS", [])
    default_apps = []
    for app_name in default_apps_names:
        app = get_fiware_default_app(request, app_name, use_idm_account=False)
        if app:
            default_apps.append(app)
    return default_apps

