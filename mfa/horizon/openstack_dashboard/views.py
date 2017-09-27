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

from django import shortcuts
import django.views.decorators.vary

import horizon
from horizon import base
from horizon import exceptions
import logging
import json
from openstack_dashboard import api

#Newly added
from openstack_dashboard import api

LOG = logging.getLogger(__name__)
LOG.info(__name__)

TWO_FACTOR_ENABLED = True

def get_user_home(user):
    dashboard = None

    LOG.info('get user home function')
    if user.is_superuser:
        try:
            dashboard = horizon.get_dashboard('admin')
        except base.NotRegistered:
            pass

    if dashboard is None:
        dashboard = horizon.get_default_dashboard()

    return dashboard.get_absolute_url()

"""
@django.views.decorators.vary.vary_on_cookie
def splash(request):
    LOG.info('Inside splash function -views.py file')
    if not request.user.is_authenticated():
	LOG.info('user authenticated check failed')
        raise exceptions.NotAuthenticated()
    LOG.info('redirect to dashboard')
    response = shortcuts.redirect(horizon.get_user_home(request.user))
    if 'logout_reason' in request.COOKIES:
        response.delete_cookie('logout_reason')
    return response
"""

@django.views.decorators.vary.vary_on_cookie
def splash(request):
    LOG.info(request.__dict__)
    LOG.info("In splash function")
    LOG.info(request.user)
    LOG.info('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$4')
    if not request.user.is_authenticated():
	LOG.info("User not autenticated ")
        raise exceptions.NotAuthenticated()
   
    user_id = api.keystone.get_user_id(request)
    print "USER CHECK"
 
    #LOG.info(user_info)
    #LOG.info('############################################')
    #LOG.info(user_info.two_factor_enabled)
    #two_factor_enabled = user_info.two_factor_enabled
    #two_factor_enabled = str2bool(two_factor_enabled)
    LOG.info('##############################################')
    tested = api.keystone.user_details(request, user_id)
    print('after tested')


    #Login case
    if TWO_FACTOR_ENABLED:
   
        #Check whether 2factor page is shown. If else show it
        if not 'totp_shown' in request.session :
            LOG.info('totp_shown is not present in the session')
            #response = shortcuts.redirect('/dashboard/otp')
	    LOG.info('redirecting to 2 factor form display page')
            response = shortcuts.redirect('/dashboard/twofactor')
        else :
            LOG.info('totp_shown value is present in session')
            if not request.session['totp_shown']:
                LOG.info('since totp_shown value is not present inside the request.session')
		LOG.info('redirecting users to twofactor form display page')
	        response = shortcuts.redirect('/dashboard/twofactor')
	LOG.info('default condition to redirect the users to two factor page')
	response = shortcuts.redirect('/dashboard/twofactor')
    else:
        print "Redirecting users to their home page/dashboard since 2FA isn't enabled"
        response = shortcuts.redirect(horizon.get_user_home(request.user))

    #Logout case
    if 'logout_reason' in request.COOKIES:
        response.delete_cookie('logout_reason')

    #Return the response corresponding to all above conditions
    return response

def str2bool(v):
    """Function For converting unicode values to bool"""
    print('Entering conversion function')
    return v.lower() in ("yes", "true", "t", "1")

def callKeystoneForTotp(request):
        """TOTP CHECK"""
        try:
                import urllib2
                totpVal = request.GET.get("totp","")
                LOG.info('TOTP value is ')
                LOG.info(totpVal)

                username = 'admin'
                password = 'demo'

                data = '{ "auth": { "identity":{ "twofactor": {"totp_value": "' + str(totpVal) + '"}, "methods": ["password","twofactor"],"password": {"user": {"name": "' + username + '","domain": { "id": "default" },"password": "'+password+'"}} } }  }'
                url = 'http://localhost:5000/v3/auth/tokens'
                req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
                LOG.info('req')
                try :
                    LOG.info('Entering try')
                    f = urllib2.urlopen(req)
                    LOG.info('HERE IN F')
                    for x in f:
                        LOG.info('x section')
                        request.session['totp_valid'] = True
                        request.session['totp_invalid'] = False
                        print "****"
                        print(x)
                    f.close()
                except Exception, e :
                    #print e
                    #request.session['otp_invalid'] = True
                    #request.session['otp_valid'] = False
                    LOG.info('exception section')
                    LOG.info(e)
                    return False

                LOG.info('session printing')
                LOG.info(request.session)
                response = shortcuts.redirect(horizon.get_user_home(request.user))
                return response
        except Exception,e:
                LOG.debug("Error occured while connecting to Keystone")
                response = shortcuts.redirect('/dashboard/totp')
                return response

