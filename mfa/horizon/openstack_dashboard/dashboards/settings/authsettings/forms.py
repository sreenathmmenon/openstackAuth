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

from datetime import datetime  # noqa
from datetime import timedelta  # noqa
import string
import pyqrcode
import babel
import babel.dates
import base64
from django.conf import settings
from django import shortcuts
from django.utils import encoding
from django.utils import translation
from django.utils.translation import ugettext_lazy as _
import pytz
import io
from horizon import exceptions
from horizon import forms
from horizon import messages
from openstack_dashboard import api
from django.core.urlresolvers import reverse_lazy
from oslo_log import log

LOG = log.getLogger(__name__)

class Manage2FAForm(forms.SelfHandlingForm):
    print "Form section"
    action      = reverse_lazy('horizon:settings:authsettings:twofactor')
    description = 'Manage two-factor authentication'
    template    = 'settings/authsettings/_two_factor.html'

    print "manage two factor"
    def clean(self):
        data = super(Manage2FAForm, self).clean()
        if self.request.POST.get('enable', None):
	    print "test"
        return data

    def handle(self, request, data):
        try:

	    user_id = api.keystone.get_user_id(request)
	    user    = api.keystone.user_get(request, user_id)
	
            secret, uri = api.keystone.get_2fa_auth_details(request, user)
            print "DSdddddddddddddddddddddddddddddddddddddddddddddddddddddDDD"
            print secret
            print uri
            print "dsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAA"
 
            LOG.info('Enabled two factor authentication or new key requested')
            
            if request.is_ajax():
                context = {}

                context['two_factor_key'] = secret
                qr = pyqrcode.create(uri, error='L')
                qr_buffer = io.BytesIO()
                qr.svg(qr_buffer, scale=5)
                context['two_factor_qr_encoded'] = base64.b64encode(qr_buffer.getvalue())
                print "#################################@@@@"
                #print qr
	        print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
		print context
		current_totp = api.keystone.generate_totp(secret)

		print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
		print current_totp
                context['hide'] = True
                return shortcuts.render(request, 'settings/authsettings/_two_factor_newkey.html', context)
            else:
                request.session['two_factor_data'] = secret
                messages.success(request, "Two factor authentication was successfully enabled.")
                return shortcuts.redirect('horizon:settings:authsettings:newkey')

        except Exception as e:
            exceptions.handle(request, 'error')
            LOG.error(e)
            return False


class Disable2FAForm(forms.SelfHandlingForm):
    action = reverse_lazy('horizon:settings:authsettings:twofactor_disable')
    description = 'Disable two factor authentication'
    template    = 'settings/authsettings/_two_factor_disable.html'

    def handle(self, request, data):
            try:

                user_id = api.keystone.get_user_id(request)
                user    = api.keystone.user_get(request, user_id)

		api.keystone.disable_2fa(request, user)
                messages.success(request, "Two factor authentication was successfully disabled for your account.")
                LOG.info('Disabled two factor authentication')
		return shortcuts.redirect('horizon:settings:authsettings:index')

            except Exception as e:
                exceptions.handle(request, 'error')
                LOG.error(e)
                return False

