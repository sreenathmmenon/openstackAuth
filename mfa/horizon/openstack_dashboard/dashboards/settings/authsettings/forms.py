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
#import os
#import sys
#import time
#import math
#import hashlib
#import hmac
#import struct

from horizon import exceptions
from horizon import forms
from horizon import messages
from openstack_dashboard import api
from django.core.urlresolvers import reverse_lazy
from oslo_log import log

LOG = log.getLogger(__name__)

def create_user_extra_data(data):
    """
    """
    extra = {'two_factor_enabled': data['two_factor_auth_enabled'],
              'secret_key': data['secret_key']}

    return extra

class UpdateTwoFactorSettingsForm(forms.SelfHandlingForm):
    #id = forms.CharField(label=_("ID"), widget=forms.HiddenInput)
    two_factor_auth_enabled = forms.BooleanField(required=False, 
                                  label=_("Enable Two Factor Authentication"),
                                  help_text=_("This option will add an extra security to your account"))
    secret_key = forms.CharField(label='Secret Key', max_length=100, )

    def handle(self, request, data):
        #data['extra'] = create_user_extra_data(data)
	data['extra'] = {'two_factor_enabled': data['two_factor_auth_enabled'],
              'secret_key': data['secret_key']}
        try:
	    print "##############################"
	    #print data
            #print  request.user.id
	    #user = request.user.id
	    print "#########################"
	    response = api.keystone.user_update(request.user.id, data['extra'])
	    print response

            #api.keystone.role_update(request, data['id'], data["extra"])
            messages.success(request, _("Role updated successfully."))
            return True
        except Exception:
            exceptions.handle(request, _('Unable to update role.'))


class TwofactorSettingsForm(forms.SelfHandlingForm):
    #language = forms.ChoiceField(label=_("Language"))
    #timezone = forms.ChoiceField(label=_("Timezone"))
    two_factor_auth_enabled  = forms.BooleanField(required=False, 
				  label=_("Enable Two Factor Authentication"),
				  help_text=_("This option will add an extra security to your account"))
    
    def __init__(self, *args, **kwargs):
        super(TwofactorSettingsForm, self).__init__(*args, **kwargs)

    def handle(self, request, data):
	"""
        try:
	
            if data:
                data['two_factor_auth_enabled'] = data['two_factor_auth_enabled'] or None
            response = api.keystone.user_update(request, user, **data)
            messages.success(request,
                             _('User has been updated successfully.'))
	    return True
        except Exception:
            messages.error(request, _('Unable to update the user.'))
            return False
	"""

class Manage2FAForm(forms.SelfHandlingForm):
    print "Form section"
    action = reverse_lazy('horizon:settings:authsettings:twofactor')
    description = 'Manage two-factor authentication'
    template = 'settings/authsettings/_two_factor.html'

    print "manage two factor"
    def clean(self):
        data = super(Manage2FAForm, self).clean()
        if self.request.POST.get('enable', None):
	    print "test"
        return data
    """
    def generate_totp(self, secret, time_range=30, i=0):
	LOG.info('generate totp function')
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
    """

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
            # NOTE(@federicofdez) Fix this to always use redirect
            if request.is_ajax():
                context = {}
		#secret='GEZDGNBVGY3TQOJQGEZDGNBVGY'
		#uri = 'otpauth://totp/{name}?secret={secret}&issuer={issuer}'.format(name='neph-test', secret=secret, issuer='Neph-test')

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
                #cache_key = uuid.uuid4().hex
                #cache.set(cache_key, (key, uri))
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
    template = 'settings/authsettings/_two_factor_disable.html'

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

