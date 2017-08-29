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

LOG = logging.getLogger(__name__)
LOG.info(__name__)

def get_user_home(user):
    dashboard = None
    if user.is_superuser:
        try:
            dashboard = horizon.get_dashboard('admin')
        except base.NotRegistered:
            pass

    if dashboard is None:
        dashboard = horizon.get_default_dashboard()

    return dashboard.get_absolute_url()

#@django.views.decorators.vary.vary_on_cookie
#def splash(request):
#    if not request.user.is_authenticated():
#        raise exceptions.NotAuthenticated()

#    response = shortcuts.redirect(horizon.get_user_home(request.user))
#    if 'logout_reason' in request.COOKIES:
#        response.delete_cookie('logout_reason')
#    return response

@django.views.decorators.vary.vary_on_cookie
def splash(request):
    LOG.info(request.__dict__)
    LOG.info("In splash function")
    if not request.user.is_authenticated():
	LOG.info("User not autenticated ")
        raise exceptions.NotAuthenticated()

    #check whether otp page is shown, if not show.
    if not 'otp_shown' in request.session :
        LOG.info('otp_shown is not present in the session')
	response = shortcuts.redirect('/dashboard/otp')
    else :
        LOG.info('otp_shown value is present in session')
	if not request.session['otp_shown']:
                LOG.info('enter-1')
		response = shortcuts.redirect('/dashboard/otp')
    response = shortcuts.redirect('/dashboard/otp')
    if 'logout_reason' in request.COOKIES:
        response.delete_cookie('logout_reason')
    #response.delete_cookie('sessionid')
    LOG.info('response returned')
    LOG.info('++++++++++++++++++++++++++++')
    LOG.info(response)
	
    return response

def callKeystone(request):
	"""
	Function to call keystone API for OTP authentication.
	This will call keystone API and do the current token authentication and will send the submitted OTP for validation.
	@param : request
	"""
        LOG.info('entering the function callKeystone')
	try :
		import urllib2
		otpVal = request.GET.get("otp","")
                LOG.info('OTP value is ')
                LOG.info(otpVal)
		"""
		data = {"auth":{"identity":{"otp":{"otp_value":+ otpVal+},"methods":["token","otp"],"token":{"id":+request.user.token.id}}}}
		#data = {"auth":{"identity":{"otp":{"otp_value":"123456"},"methods":["token","otp"],"token":{"id":"d7715c3389c94a0489447c4700936369"}}}}
                LOG.info(data)

		url = 'http://localhost:5000/v3/auth//tokens'
                #url = 'http://localhost:5000/v2.0/tokens'
		LOG.info('after url')
                values = {"auth":{"passwordCredentials":{"username":"admin", "password": "demo"}}}
                params = json.dumps(data)
                LOG.info('after params')
	        #headers = {"Content-type":"application/json","Accept": "application/json"}
	 	headers = {'Content-Type': 'application/json','X-Auth-Token':request.user.token.id}
                req = urllib2.Request(url, params, headers)
		LOG.info(req)
		LOG.info(req.__dict__)
                #response = urllib2.urlopen(req)

                #data = response.read()
                #text = json.loads(data)

                LOG.info(req)
		#req = urllib2.Request(url, data, {'Content-Type': 'application/json','X-Auth-Token':request.user.token.id})
		"""		
	        username = 'admin'
		password = 'demo'

		data = '{ "auth": { "identity":{ "otp": {"otp_value": "' + str(otpVal) + '"}, "methods": ["password","otp"],"password": {"user": {"name": "' + username + '","domain": { "id": "default" },"password": "'+password+'"}} } }  }'
		url = 'http://localhost:5000/v3/auth/tokens'
		req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
		LOG.info('req')
		try :
		    LOG.info('Entering try')
		    f = urllib2.urlopen(req)
		    LOG.info('HERE IN F')
		    for x in f:
			LOG.info('x section')
     		        request.session['otp_valid'] = True
			request.session['otp_invalid'] = False
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
		response = shortcuts.redirect('/dashboard/otp')
	        return response
