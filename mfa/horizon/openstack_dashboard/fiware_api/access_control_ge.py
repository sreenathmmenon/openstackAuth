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

import logging
import requests

from django.conf import settings
from django.template.loader import render_to_string
from xml.etree import ElementTree

from openstack_dashboard.fiware_api import keystone

LOG = logging.getLogger('idm_logger')

XACML_TEMPLATE = 'access_control/policy_set.xacml'
DOMAIN_TEMPLATE = 'access_control/domain.xacml'

def get_application_domain(request, application):
    """Checks if application has an associated domain in AC. If not, it creates it.
    """

    if not application.extra.has_key('ac_domain'):
        LOG.debug('Access Control Domain not created, creating it...')

        context = {
            'app_id': application.id,
            'app_name': application.name
        }

        xml = render_to_string(DOMAIN_TEMPLATE, context)
        
        headers = {
            'Accept': 'application/xml',
            'content-type': 'application/xml;charset=UTF-8',
            'X-Auth-Token': settings.ACCESS_CONTROL_MAGIC_KEY
        }

        url = settings.ACCESS_CONTROL_URL + '/authzforce/domains'

        # LOG.debug('BODY: %s', xml)
        # LOG.debug('URL: %s', url)
        # LOG.debug('HEADERS: %s', headers)

        response = requests.post(
            url,
            data=xml,
            headers=headers,
            verify=False)

        tree = ElementTree.fromstring(response.content)

        domain_id = tree.attrib['href']

        LOG.debug('Domain created: %s', domain_id)

        application = keystone.application_update(
            request, 
            application.id, 
            ac_domain=domain_id)

    LOG.debug('Access Control Domain for application %s: %s', application.id, application.extra['ac_domain'])
    return application.extra['ac_domain']

def policyset_update(request, application, role_permissions):
    """Gets all role's permissions and generates a xacml file to
    update the Access Control.
    """
    if not settings.ACCESS_CONTROL_URL:
        LOG.warning('ACCESS_CONTROL_URL setting is not set.')
        return

    if not settings.ACCESS_CONTROL_MAGIC_KEY:
        LOG.warning('ACCESS_CONTROL_MAGIC_KEY setting is not set.')
        return 

    app_id = application.id

    context = {
        'policy_set_description': 'TODO',
        'role_permissions': role_permissions,
        'app_id': app_id,
    }

    xml = render_to_string(XACML_TEMPLATE, context)
    # LOG.debug('XACML: %s', xml)

    headers = {
        'content-type': 'application/xml',
        'X-Auth-Token': settings.ACCESS_CONTROL_MAGIC_KEY
    }

    domain = get_application_domain(request, application)

    url = settings.ACCESS_CONTROL_URL + '/authzforce/domains/' + domain + '/pap/policySet'

    LOG.debug('Sending request to : %s', url)

    response = requests.put(
        url,
        data=xml,
        headers=headers,
        verify=False)

    LOG.debug('Response code from the AC GE: %s', response.status_code)

    return response
