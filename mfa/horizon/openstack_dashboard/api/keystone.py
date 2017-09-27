# Copyright 2012 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
# Copyright 2012 OpenStack Foundation
# Copyright 2012 Nebula, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import logging

###For 2Factor Authentication
import os
import base64
import io
import os
import sys
import time
import math
import hashlib
import hmac
import struct
import base64
from keystoneauth1.identity import v2
from keystoneauth1 import session
from keystoneclient.v2_0 import client as kclient
###

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
import six
import six.moves.urllib.parse as urlparse

from keystoneclient import exceptions as keystone_exceptions

from openstack_auth import backend
from openstack_auth import utils as auth_utils

from horizon import exceptions
from horizon import messages
from horizon.utils import functions as utils

from openstack_dashboard.api import base
from openstack_dashboard import policy


LOG = logging.getLogger(__name__)
DEFAULT_ROLE = None


# Set up our data structure for managing Identity API versions, and
# add a couple utility methods to it.
class IdentityAPIVersionManager(base.APIVersionManager):
    def upgrade_v2_user(self, user):
        if getattr(user, "project_id", None) is None:
            user.project_id = getattr(user, "default_project_id",
                                      getattr(user, "tenantId", None))
        return user

    def get_project_manager(self, *args, **kwargs):
        if VERSIONS.active < 3:
            manager = keystoneclient(*args, **kwargs).tenants
        else:
            manager = keystoneclient(*args, **kwargs).projects
        return manager


VERSIONS = IdentityAPIVersionManager(
    "identity", preferred_version=auth_utils.get_keystone_version())


# Import from oldest to newest so that "preferred" takes correct precedence.
try:
    from keystoneclient.v2_0 import client as keystone_client_v2
    VERSIONS.load_supported_version(2.0, {"client": keystone_client_v2})
except ImportError:
    pass

try:
    from keystoneclient.v3 import client as keystone_client_v3
    VERSIONS.load_supported_version(3, {"client": keystone_client_v3})
except ImportError:
    pass


@six.python_2_unicode_compatible
class Service(base.APIDictWrapper):
    """Wrapper for a dict based on the service data from keystone."""
    _attrs = ['id', 'type', 'name']

    def __init__(self, service, region, *args, **kwargs):
        super(Service, self).__init__(service, *args, **kwargs)
        self.public_url = base.get_url_for_service(service, region,
                                                   'publicURL')
        self.url = base.get_url_for_service(service, region, 'internalURL')
        if self.url:
            self.host = urlparse.urlparse(self.url).hostname
        else:
            self.host = None
        self.disabled = None
        self.region = region

    def __str__(self):
        if(self.type == "identity"):
            return _("%(type)s (%(backend)s backend)") \
                % {"type": self.type, "backend": keystone_backend_name()}
        else:
            return self.type

    def __repr__(self):
        return "<Service: %s>" % six.text_type(self)


def _get_endpoint_url(request, endpoint_type, catalog=None):
    if getattr(request.user, "service_catalog", None):
        url = base.url_for(request,
                           service_type='identity',
                           endpoint_type=endpoint_type)
    else:
        auth_url = getattr(settings, 'OPENSTACK_KEYSTONE_URL')
        url = request.session.get('region_endpoint', auth_url)

    # TODO(gabriel): When the Service Catalog no longer contains API versions
    # in the endpoints this can be removed.
    url = url.rstrip('/')
    url = urlparse.urljoin(url, 'v%s' % VERSIONS.active)

    return url

def kclient_connect(request):
    print 'entering'
    #Getting the details of the user
    KEYSTONE_ADMIN_TENANT_ID  = ''
    KEYSTONE_ADMIN_USER_ID    = ''
    tenant_id          = getattr(settings, 'KEYSTONE_ADMIN_TENANT_ID',    '')
    admin_user_id      = getattr(settings, 'KEYSTONE_ADMIN_USER_ID',      '')
    
    tenant_name  = getattr(settings, 'admin',  '')
    user_name    = getattr(settings, 'admin',    '')
    auth_url     = getattr(settings, 'http://198.100.181.73:5000/v2.0',     '')
    password     = getattr(settings, 'demo',     '')

    tenant_id = ''
    tenant_name = 'admin'
    user_name = 'admin'
    password = 'demo'
    auth_url = 'http://198.100.181.73:5000/v2.0'

    #Making the dictionary to save the data
    keystone_cred = {}
        
    #Saving the details to dictionary
    if tenant_id:
        keystone_cred['tenant_id'] = tenant_id
    else:
        keystone_cred['tenant_name'] = tenant_name
    if admin_user_id:
        keystone_cred['user_id'] = admin_user_id
    else:
        keystone_cred['username'] = user_name

    print 'entering-2'
    keystone_cred['password'] = password
    keystone_cred['auth_url'] = auth_url
    print keystone_cred
    auth = v2.Password(**keystone_cred)
    sess = session.Session(auth=auth)
    keystone = kclient.Client(session=sess)
    """
    print 'entering -3'
    print user_id
    user   = keystone.users.get(user_id)
    print 'enetring -4'
    print user
    return user
    """
    return keystone

def keystoneclient(request, admin=False):
    """Returns a client connected to the Keystone backend.

    Several forms of authentication are supported:

        * Username + password -> Unscoped authentication
        * Username + password + tenant id -> Scoped authentication
        * Unscoped token -> Unscoped authentication
        * Unscoped token + tenant id -> Scoped authentication
        * Scoped token -> Scoped authentication

    Available services and data from the backend will vary depending on
    whether the authentication was scoped or unscoped.

    Lazy authentication if an ``endpoint`` parameter is provided.

    Calls requiring the admin endpoint should have ``admin=True`` passed in
    as a keyword argument.

    The client is cached so that subsequent API calls during the same
    request/response cycle don't have to be re-authenticated.
    """
    user = request.user
    print('1')
    if admin:
        print('2')
        
        if not policy.check((("identity", "admin_required"),), request):
            print('3')
            raise exceptions.NotAuthorized
        
        endpoint_type = 'adminURL'
    else:
        print('4')
        endpoint_type = getattr(settings,
                                'OPENSTACK_ENDPOINT_TYPE',
                                'internalURL')

    api_version = VERSIONS.get_active_version()
    print api_version
    print('api version -5')

    # Take care of client connection caching/fetching a new client.
    # Admin vs. non-admin clients are cached separately for token matching.
    cache_attr = "_keystoneclient_admin" if admin \
        else backend.KEYSTONE_CLIENT_ATTR
    if (hasattr(request, cache_attr) and
        (not user.token.id or
         getattr(request, cache_attr).auth_token == user.token.id)):
        print('6')
        conn = getattr(request, cache_attr)
    else:
        print('7')
        endpoint = _get_endpoint_url(request, endpoint_type)
        insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
        cacert = getattr(settings, 'OPENSTACK_SSL_CACERT', None)
        LOG.debug("Creating a new keystoneclient connection to %s." % endpoint)
        remote_addr = request.environ.get('REMOTE_ADDR', '')
        conn = api_version['client'].Client(token=user.token.id,
                                            endpoint=endpoint,
                                            original_ip=remote_addr,
                                            insecure=insecure,
                                            cacert=cacert,
                                            auth_url=endpoint,
                                            debug=settings.DEBUG)
        print('8')
	print(conn.__dict__)
        setattr(request, cache_attr, conn)
    print(conn.__dict__)
    return conn


def domain_create(request, name, description=None, enabled=None):
    manager = keystoneclient(request, admin=True).domains
    return manager.create(name,
                          description=description,
                          enabled=enabled)


def domain_get(request, domain_id):
    manager = keystoneclient(request, admin=True).domains
    return manager.get(domain_id)


def domain_delete(request, domain_id):
    manager = keystoneclient(request, admin=True).domains
    return manager.delete(domain_id)


def domain_list(request):
    manager = keystoneclient(request, admin=True).domains
    return manager.list()


def domain_update(request, domain_id, name=None, description=None,
                  enabled=None):
    manager = keystoneclient(request, admin=True).domains
    return manager.update(domain_id, name, description, enabled)


def tenant_create(request, name, description=None, enabled=None,
                  domain=None, **kwargs):
    manager = VERSIONS.get_project_manager(request, admin=True)
    try:
        if VERSIONS.active < 3:
            return manager.create(name, description, enabled, **kwargs)
        else:
            return manager.create(name, domain,
                                  description=description,
                                  enabled=enabled, **kwargs)
    except keystone_exceptions.Conflict:
        raise exceptions.Conflict()


def get_default_domain(request):
    """Gets the default domain object to use when creating Identity object.

    Returns the domain context if is set, otherwise return the domain
    of the logon user.
    """
    domain_id = request.session.get("domain_context", None)
    domain_name = request.session.get("domain_context_name", None)
    # if running in Keystone V3 or later
    if VERSIONS.active >= 3 and not domain_id:
        # if no domain context set, default to users' domain
        domain_id = request.user.user_domain_id
        try:
            domain = domain_get(request, domain_id)
            domain_name = domain.name
        except Exception:
            LOG.warning("Unable to retrieve Domain: %s" % domain_id)
    domain = base.APIDictWrapper({"id": domain_id,
                                  "name": domain_name})
    return domain


# TODO(gabriel): Is there ever a valid case for admin to be false here?
# A quick search through the codebase reveals that it's always called with
# admin=true so I suspect we could eliminate it entirely as with the other
# tenant commands.
def tenant_get(request, project, admin=True):
    manager = VERSIONS.get_project_manager(request, admin=admin)
    return manager.get(project)


def tenant_delete(request, project):
    manager = VERSIONS.get_project_manager(request, admin=True)
    return manager.delete(project)


def tenant_list(request, paginate=False, marker=None, domain=None, user=None,
                admin=True, filters=None):
    manager = VERSIONS.get_project_manager(request, admin=admin)
    page_size = utils.get_page_size(request)

    limit = None
    if paginate:
        limit = page_size + 1

    has_more_data = False

    # if requesting the projects for the current user,
    # return the list from the cache
    if user == request.user.id:
        tenants = request.user.authorized_tenants

    elif VERSIONS.active < 3:
        tenants = manager.list(limit, marker)
        if paginate and len(tenants) > page_size:
            tenants.pop(-1)
            has_more_data = True
    else:
        kwargs = {
            "domain": domain,
            "user": user
        }
        if filters is not None:
            kwargs.update(filters)
        tenants = manager.list(**kwargs)
    return (tenants, has_more_data)


def tenant_update(request, project, name=None, description=None,
                  enabled=None, domain=None, **kwargs):
    manager = VERSIONS.get_project_manager(request, admin=True)
    try:
        if VERSIONS.active < 3:
            return manager.update(project, name, description, enabled,
                                  **kwargs)
        else:
            return manager.update(project, name=name, description=description,
                                  enabled=enabled, domain=domain, **kwargs)
    except keystone_exceptions.Conflict:
        raise exceptions.Conflict()


def user_list(request, project=None, domain=None, group=None, filters=None):
    if VERSIONS.active < 3:
        kwargs = {"tenant_id": project}
    else:
        kwargs = {
            "project": project,
            "domain": domain,
            "group": group
        }
        if filters is not None:
            kwargs.update(filters)
    users = keystoneclient(request, admin=True).users.list(**kwargs)
    return [VERSIONS.upgrade_v2_user(user) for user in users]


def user_create(request, name=None, email=None, password=None, project=None,
                enabled=None, domain=None, description=None):
    manager = keystoneclient(request, admin=True).users
    try:
        if VERSIONS.active < 3:
            user = manager.create(name, password, email, project, enabled)
            return VERSIONS.upgrade_v2_user(user)
        else:
            return manager.create(name, password=password, email=email,
                                  default_project=project, enabled=enabled,
                                  domain=domain, description=description)
    except keystone_exceptions.Conflict:
        raise exceptions.Conflict()


def user_delete(request, user_id):
    return keystoneclient(request, admin=True).users.delete(user_id)


def user_get(request, user_id, admin=True):
    user = keystoneclient(request, admin=admin).users.get(user_id)
    return VERSIONS.upgrade_v2_user(user)


def user_update(request, user, **data):
    manager = keystoneclient(request, admin=True).users
    error = None

    if not keystone_can_edit_user():
        raise keystone_exceptions.ClientException(
            405, _("Identity service does not allow editing user data."))

    # The v2 API updates user model and default project separately
    if VERSIONS.active < 3:
        project = data.pop('project')

        # Update user details
        try:
            user = manager.update(user, **data)
	    print "%%%%%%%%%%%%%%%%%%%%%%%%%%";
	    print user
        except keystone_exceptions.Conflict:
            raise exceptions.Conflict()
        except Exception:
            error = exceptions.handle(request, ignore=True)
            print error

        # Update default tenant
        try:
            user_update_tenant(request, user, project)
            user.tenantId = project
        except Exception:
            error = exceptions.handle(request, ignore=True)

        # Check for existing roles
        # Show a warning if no role exists for the project
        user_roles = roles_for_user(request, user, project)
        if not user_roles:
            messages.warning(request,
                             _('User %s has no role defined for '
                               'that project.')
                             % data.get('name', None))

        if error is not None:
            raise error

    # v3 API is so much simpler...
    else:
        try:
            user = manager.update(user, **data)
        except keystone_exceptions.Conflict:
            raise exceptions.Conflict()


def user_update_enabled(request, user, enabled):
    manager = keystoneclient(request, admin=True).users
    if VERSIONS.active < 3:
        return manager.update_enabled(user, enabled)
    else:
        return manager.update(user, enabled=enabled)


def user_update_password(request, user, password, admin=True):

    if not keystone_can_edit_user():
        raise keystone_exceptions.ClientException(
            405, _("Identity service does not allow editing user password."))

    manager = keystoneclient(request, admin=admin).users
    if VERSIONS.active < 3:
        return manager.update_password(user, password)
    else:
        return manager.update(user, password=password)


def user_verify_admin_password(request, admin_password):
    # attempt to create a new client instance with admin password to
    # verify if it's correct.
    client = keystone_client_v2 if VERSIONS.active < 3 else keystone_client_v3
    try:
        endpoint = _get_endpoint_url(request, 'internalURL')
        insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
        cacert = getattr(settings, 'OPENSTACK_SSL_CACERT', None)
        client.Client(
            username=request.user.username,
            password=admin_password,
            insecure=insecure,
            cacert=cacert,
            auth_url=endpoint
        )
        return True
    except Exception:
        exceptions.handle(request, ignore=True)
        return False

######Section Used for 2 Factor Authentication
def get_user_id(request):
    """Fetch the id corresponding to a user"""
    client = keystoneclient(request, admin=False)
    client.user_id = request.user.id
    return client.user_id

def user_details(request, user_id):
    """Fetch the information of any user"""

    keystone = kclient_connect(request)
    print('user_details function entering')
    user = keystone.users.get(user_id)
    return user



def generate_2fa_uri(secret):
    """Generate a uri based on secret key.

    QR codes to be scanned by Google Authenticator app 
    are being generated based on this uri.
   
    Args:
        secret: the unique secret key which is required for generating the uri
    Returns:
        uri: a uri which can be used for generating the QR code

    """
    uri = 'otpauth://totp/{name}?secret={secret}&issuer={issuer}'.format(name='neph-test', secret=secret, issuer='Neph-test')
    return uri

def get_2fa_auth_details(request, user):
    """Generates a random secret key and pass it to generate the unique uri."""
    secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    #Generate the uri based on the above generated secret key
    uri    = generate_2fa_uri(secret)
    return secret, uri

def enable_2fa(request, user, **data):
    """To enable two factor authentication for a user.

     Args:
         user: details corresponding to the user for whom the 2fa is to be enabled
         data: array containing the details which are to be updated corresponding to 
               this user in DB.
    Return:
        Enable 2FA for the user

    """

    print "entering here"
    #data = {}
    data['two_factor_enabled'] = True

    if user_update_2fa_details(request, user, **data):
        print "entered into user_update function loop for enabling 2FA"
        return True
    else:
        print "user_update failure for 2FA"
        return False

def disable_2fa(request, user):
    """To disable two factor authentication for a user.

    Args:
        user: details corresponding to the user for whom the 2FA is to be disabled.

    Return:
        Disable 2FA for the user.

    """

    print "entering here"
    data = {}
    data['two_factor_enabled'] = False
    
    if user_update_2fa_details(request, user, **data):
        print "entered into user_update function loop for disabling 2FA"
        return True
    else:
        print "user_update failure"
        return False

def user_update_2fa_details(request, user, **data):
    """To update the 2fa details in DB"""

    #manager = keystoneclient(request, admin=True).users
    manager = kclient_connect(request).users
    print manager
    print '%%%%%%%%%%%%%%%%%%%%%%%5'
    if manager.update(user, **data):
        print "success"
        return True
    else:
        print "FAILURE"
        return False

def auth_2fa_is_enabled(request, user):
    """Check if 2FA is enabled for the user or not.

    Args:
        user: details corresponding to the user

    Return:
        Return true is 2FA has been enabled.
  
    """

    manager = keystoneclient(request, admin=True).users
    print "$$$$$Entering 2fa enabked checking function"
    return True

def generate_totp(secret, time_range=30, i=0):
    """Algorithm for generating the Time Based One Time Password.

    Using this function we generate and find the unique TOTP value corresponding to a 
    secret key at the current moment. TOTP values are Time based and valid for only a 
    few seconds.

    Args:
       secret: unique secret key using which we find the current TOTP value
   
    Return:
        The unique TOTP value based on the current time.

    """

    print('generate totp function')

    #Converting the secret key
    secret = base64.b32decode(secret, True)
    tm = int(time.time() / time_range)
    b = struct.pack(">q", tm + i)
    print type(secret)
    secret = str(secret)
    print type(secret)
    hm = hmac.HMAC(secret, b, hashlib.sha1).digest()
    offset = ord(hm[-1]) & 0x0F
    truncatedHash = hm[offset:offset + 4]
    code = struct.unpack(">L", truncatedHash)[0]
    code &= 0x7FFFFFFF
    code %= 1000000
    LOG.info('codeeeee')
    return "%06d" % code

#####End of Section used for 2Factor Authentication

def user_update_own_password(request, origpassword, password):
    client = keystoneclient(request, admin=False)
    client.user_id = request.user.id
    if VERSIONS.active < 3:
        return client.users.update_own_password(origpassword, password)
    else:
        return client.users.update_password(origpassword, password)


def user_update_tenant(request, user, project, admin=True):
    manager = keystoneclient(request, admin=admin).users
    if VERSIONS.active < 3:
        return manager.update_tenant(user, project)
    else:
        return manager.update(user, project=project)


def group_create(request, domain_id, name, description=None):
    manager = keystoneclient(request, admin=True).groups
    return manager.create(domain=domain_id,
                          name=name,
                          description=description)


def group_get(request, group_id, admin=True):
    manager = keystoneclient(request, admin=admin).groups
    return manager.get(group_id)


def group_delete(request, group_id):
    manager = keystoneclient(request, admin=True).groups
    return manager.delete(group_id)


def group_list(request, domain=None, project=None, user=None):
    manager = keystoneclient(request, admin=True).groups
    groups = manager.list(user=user, domain=domain)

    if project:
        project_groups = []
        for group in groups:
            roles = roles_for_group(request, group=group.id, project=project)
            if roles and len(roles) > 0:
                project_groups.append(group)
        groups = project_groups

    return groups


def group_update(request, group_id, name=None, description=None):
    manager = keystoneclient(request, admin=True).groups
    return manager.update(group=group_id,
                          name=name,
                          description=description)


def add_group_user(request, group_id, user_id):
    manager = keystoneclient(request, admin=True).users
    return manager.add_to_group(group=group_id, user=user_id)


def remove_group_user(request, group_id, user_id):
    manager = keystoneclient(request, admin=True).users
    return manager.remove_from_group(group=group_id, user=user_id)


def get_project_groups_roles(request, project):
    """Gets the groups roles in a given project.

    :param request: the request entity containing the login user information
    :param project: the project to filter the groups roles. It accepts both
                    project object resource or project ID

    :returns group_roles: a dictionary mapping the groups and their roles in
                          given project

    """
    groups_roles = collections.defaultdict(list)
    project_role_assignments = role_assignments_list(request,
                                                     project=project)
    for role_assignment in project_role_assignments:
        if not hasattr(role_assignment, 'group'):
            continue
        group_id = role_assignment.group['id']
        role_id = role_assignment.role['id']
        groups_roles[group_id].append(role_id)
    return groups_roles


def role_assignments_list(request, project=None, user=None, role=None,
                          group=None, domain=None, effective=False):
    if VERSIONS.active < 3:
        raise exceptions.NotAvailable

    manager = keystoneclient(request, admin=True).role_assignments
    return manager.list(project=project, user=user, role=role, group=group,
                        domain=domain, effective=effective)


def role_create(request, name):
    manager = keystoneclient(request, admin=True).roles
    return manager.create(name)


def role_get(request, role_id):
    manager = keystoneclient(request, admin=True).roles
    return manager.get(role_id)


def role_update(request, role_id, name=None):
    manager = keystoneclient(request, admin=True).roles
    return manager.update(role_id, name)


def role_delete(request, role_id):
    manager = keystoneclient(request, admin=True).roles
    return manager.delete(role_id)


def role_list(request):
    """Returns a global list of available roles."""
    return keystoneclient(request, admin=True).roles.list()


def roles_for_user(request, user, project=None, domain=None):
    """Returns a list of user roles scoped to a project or domain."""
    manager = keystoneclient(request, admin=True).roles
    if VERSIONS.active < 3:
        return manager.roles_for_user(user, project)
    else:
        return manager.list(user=user, domain=domain, project=project)


def get_domain_users_roles(request, domain):
    users_roles = collections.defaultdict(list)
    domain_role_assignments = role_assignments_list(request,
                                                    domain=domain)
    for role_assignment in domain_role_assignments:
        if not hasattr(role_assignment, 'user'):
            continue
        user_id = role_assignment.user['id']
        role_id = role_assignment.role['id']
        users_roles[user_id].append(role_id)
    return users_roles


def add_domain_user_role(request, user, role, domain):
    """Adds a role for a user on a domain."""
    manager = keystoneclient(request, admin=True).roles
    return manager.grant(role, user=user, domain=domain)


def remove_domain_user_role(request, user, role, domain=None):
    """Removes a given single role for a user from a domain."""
    manager = keystoneclient(request, admin=True).roles
    return manager.revoke(role, user=user, domain=domain)


def get_project_users_roles(request, project):
    users_roles = collections.defaultdict(list)
    if VERSIONS.active < 3:
        project_users = user_list(request, project=project)

        for user in project_users:
            roles = roles_for_user(request, user.id, project)
            roles_ids = [role.id for role in roles]
            users_roles[user.id].extend(roles_ids)
    else:
        project_role_assignments = role_assignments_list(request,
                                                         project=project)
        for role_assignment in project_role_assignments:
            if not hasattr(role_assignment, 'user'):
                continue
            user_id = role_assignment.user['id']
            role_id = role_assignment.role['id']
            users_roles[user_id].append(role_id)
    return users_roles


def add_tenant_user_role(request, project=None, user=None, role=None,
                         group=None, domain=None):
    """Adds a role for a user on a tenant."""
    manager = keystoneclient(request, admin=True).roles
    if VERSIONS.active < 3:
        return manager.add_user_role(user, role, project)
    else:
        return manager.grant(role, user=user, project=project,
                             group=group, domain=domain)


def remove_tenant_user_role(request, project=None, user=None, role=None,
                            group=None, domain=None):
    """Removes a given single role for a user from a tenant."""
    manager = keystoneclient(request, admin=True).roles
    if VERSIONS.active < 3:
        return manager.remove_user_role(user, role, project)
    else:
        return manager.revoke(role, user=user, project=project,
                              group=group, domain=domain)


def remove_tenant_user(request, project=None, user=None, domain=None):
    """Removes all roles from a user on a tenant, removing them from it."""
    client = keystoneclient(request, admin=True)
    roles = client.roles.roles_for_user(user, project)
    for role in roles:
        remove_tenant_user_role(request, user=user, role=role.id,
                                project=project, domain=domain)


def roles_for_group(request, group, domain=None, project=None):
    manager = keystoneclient(request, admin=True).roles
    return manager.list(group=group, domain=domain, project=project)


def add_group_role(request, role, group, domain=None, project=None):
    """Adds a role for a group on a domain or project."""
    manager = keystoneclient(request, admin=True).roles
    return manager.grant(role=role, group=group, domain=domain,
                         project=project)


def remove_group_role(request, role, group, domain=None, project=None):
    """Removes a given single role for a group from a domain or project."""
    manager = keystoneclient(request, admin=True).roles
    return manager.revoke(role=role, group=group, project=project,
                          domain=domain)


def remove_group_roles(request, group, domain=None, project=None):
    """Removes all roles from a group on a domain or project."""
    client = keystoneclient(request, admin=True)
    roles = client.roles.list(group=group, domain=domain, project=project)
    for role in roles:
        remove_group_role(request, role=role.id, group=group,
                          domain=domain, project=project)


def get_default_role(request):
    """Gets the default role object from Keystone and saves it as a global.

    Since this is configured in settings and should not change from request
    to request. Supports lookup by name or id.
    """
    global DEFAULT_ROLE
    default = getattr(settings, "OPENSTACK_KEYSTONE_DEFAULT_ROLE", None)
    if default and DEFAULT_ROLE is None:
        try:
            roles = keystoneclient(request, admin=True).roles.list()
        except Exception:
            roles = []
            exceptions.handle(request)
        for role in roles:
            if role.id == default or role.name == default:
                DEFAULT_ROLE = role
                break
    return DEFAULT_ROLE


def ec2_manager(request):
    client = keystoneclient(request)
    if hasattr(client, 'ec2'):
        return client.ec2

    # Keystoneclient 4.0 was released without the ec2 creds manager.
    from keystoneclient.v2_0 import ec2
    return ec2.CredentialsManager(client)


def list_ec2_credentials(request, user_id):
    return ec2_manager(request).list(user_id)


def create_ec2_credentials(request, user_id, tenant_id):
    return ec2_manager(request).create(user_id, tenant_id)


def get_user_ec2_credentials(request, user_id, access_token):
    return ec2_manager(request).get(user_id, access_token)


def keystone_can_edit_domain():
    backend_settings = getattr(settings, "OPENSTACK_KEYSTONE_BACKEND", {})
    can_edit_domain = backend_settings.get('can_edit_domain', True)
    multi_domain_support = getattr(settings,
                                   'OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT',
                                   False)
    return can_edit_domain and multi_domain_support


def keystone_can_edit_user():
    backend_settings = getattr(settings, "OPENSTACK_KEYSTONE_BACKEND", {})
    return backend_settings.get('can_edit_user', True)


def keystone_can_edit_project():
    backend_settings = getattr(settings, "OPENSTACK_KEYSTONE_BACKEND", {})
    return backend_settings.get('can_edit_project', True)


def keystone_can_edit_group():
    backend_settings = getattr(settings, "OPENSTACK_KEYSTONE_BACKEND", {})
    return backend_settings.get('can_edit_group', True)


def keystone_can_edit_role():
    backend_settings = getattr(settings, "OPENSTACK_KEYSTONE_BACKEND", {})
    return backend_settings.get('can_edit_role', True)


def keystone_backend_name():
    if hasattr(settings, "OPENSTACK_KEYSTONE_BACKEND"):
        return settings.OPENSTACK_KEYSTONE_BACKEND['name']
    else:
        return 'unknown'


def get_version():
    return VERSIONS.active
