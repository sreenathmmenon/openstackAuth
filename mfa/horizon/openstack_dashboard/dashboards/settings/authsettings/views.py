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

from django.conf import settings
from django.core.urlresolvers import reverse_lazy
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import redirect

from horizon import forms
from horizon import views
from horizon.utils import functions as utils
from openstack_dashboard.dashboards.settings.authsettings import forms as twofactor_forms

from horizon import tabs
from openstack_dashboard import api

from django.http import JsonResponse

def validate_code(request):
    """To validate the TOTP code entered by the user for enabling 2FA"""
    user_id = api.keystone.get_user_id(request)
    print "USER CHECK"
    print user_id
    user            = api.keystone.user_get(request, user_id)
    user_auth_code  = request.GET.get('auth_code', None)
    secret          = request.GET.get('secret', None)

    #Generate a code form our side using algorithm and use it to validate
    generated_code  = api.keystone.generate_totp(secret)

    print secret
    print user_auth_code
    print generated_code
    print 'entering code comparison'
    
    data  = {}
    extra = {}

    #Code comparison
    if user_auth_code == generated_code:
        data['totp_authenticated'] = True
        extra['two_factor_enabled'] = True
	extra['secret_key'] = secret
        api.keystone.enable_2fa(request, user, **extra)
    else:
  	print 'falseeeeee'
        data['totp_authenticated'] = False
    return JsonResponse(data)


class Manage2FAView(forms.ModalFormView):
    """View for Managing the 2Factor Authentication Settings""" 
   
    form_class    = twofactor_forms.Manage2FAForm
    print "test";
    template_name = 'settings/authsettings/two_factor.html'
    print "after template"

    def get_context_data(self, **kwargs):
        print "get context section"
        context = super(Manage2FAView, self).get_context_data(**kwargs)
        print "after context"

	print "###################"

    	#Fetching the userid and using that to get the full user information	
	user_id = api.keystone.get_user_id(self.request)
        user    = api.keystone.user_get(self.request, user_id)

	print "#################Views page #########################"
    	print user
    	print type(user.two_factor_enabled)

	#Checking whether user has enabled 2FA
     	two_factor_enabled = user.two_factor_enabled

    	#Fetching the user's phone number
    	user_phone_number  = user.phone

	#Converting to bool to fix errors
    	if type(two_factor_enabled) == unicode:
	    print "Entering the loop sinc etype is unicode"
	    two_factor_enabled = self.str2bool(two_factor_enabled)

    	#Set true if the user has enabled 2FA
    	if two_factor_enabled:
	        context['two_factor_enabled'] = True
	        context['user_phone_number']  = user_phone_number
    	else:
	        context['two_factor_enabled'] = False
        return context


    def str2bool(self, v):
        """Function For converting unicode values to bool"""
   	print('Entering conversion function')
        return v.lower() in ("yes", "true", "t", "1")

class Disable2FAView(forms.ModalFormView):
    form_class = twofactor_forms.Disable2FAForm
    template_name = 'settings/authsettings/two_factor_disable.html'

    def dispatch(self, request, *args, **kwargs):
        user_id = self.request.user.id
        user    = api.keystone.user_get(request, user_id)

	if not user.two_factor_enabled:
	    print "Two factor not enabled"
            return redirect('horizon:settings:authsettings:index')

        print "returning section"
        return super(Disable2FAView, self).dispatch(request, args, kwargs)

class Manage2FAKeyView(views.APIView):
    print('Enteringgggg')
    template_name = 'settings/authsettings/two_factor_newkey.html'

    def get_template_names(self):
        if self.request.is_ajax():
            if not hasattr(self, "ajax_template_name"):
                
                # Transform standard template name to ajax name (leading "_")
                bits = list(os.path.split(self.template_name))
                bits[1] = "".join(("_", bits[1]))
                self.ajax_template_name = os.path.join(*bits)
            template = self.ajax_template_name
        else:
            template = self.template_name
        return template

    def get_context_data(self, **kwargs):
        context = super(Manage2FAKeyView, self).get_context_data(**kwargs)
        cache_key = self.request.session['two_factor_data']
        del self.request.session['two_factor_data']
        return context


    def dispatch(self, request, *args, **kwargs):
        #if 'two_factor_data' not in self.request.session:
        #return redirect('horizon:settings:authsettings:index')
        return super(Manage2FAKeyView, self).dispatch(request, args, kwargs)


