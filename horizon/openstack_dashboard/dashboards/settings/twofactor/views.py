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

from horizon import forms
from horizon.utils import functions as utils
from openstack_dashboard.dashboards.settings.twofactor import forms as twofactor_forms


class TwoFactorAuthView(forms.ModalFormView):
    form_class = twofactor_forms.TwofactorSettingsForm
    form_id = "two_factor_modal"
    modal_header = _("Two Factor Authentication")
    modal_id = "two_factor_modal"
    page_title = _("Two Factor Authentication")
    submit_label = _("Save")
    submit_url = reverse_lazy("horizon:settings:twofactor:index")
    template_name = 'settings/twofactor/twofactor.html'

    def get_initial(self):
        return {
            'language': self.request.session.get(
                settings.LANGUAGE_COOKIE_NAME,
                self.request.COOKIES.get(settings.LANGUAGE_COOKIE_NAME,
                                         self.request.LANGUAGE_CODE)),
            'timezone': self.request.session.get(
                'django_timezone',
                self.request.COOKIES.get('django_timezone', 'UTC')),
            'pagesize': utils.get_page_size(self.request),
            'instance_log_length': utils.get_log_length(self.request)}

    def form_valid(self, form):
        return form.handle(self.request, form.cleaned_data)
