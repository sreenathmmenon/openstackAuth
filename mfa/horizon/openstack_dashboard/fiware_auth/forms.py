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

import os

from nocaptcha_recaptcha.fields import NoReCaptchaField
from nocaptcha_recaptcha.widgets import NoReCaptchaWidget

from django import forms
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe

from openstack_auth import forms as openstack_auth_forms

from keystoneclient import exceptions as keystoneclient_exceptions

from openstack_dashboard import fiware_api


TRIAL_USER_MESSAGE = 'auth/_trial_users_not_available.html'

class ConfirmPasswordForm(forms.Form):
    """Encapsulates the idea of two password fields and checking they are the same"""
    password1 = forms.CharField(widget=forms.PasswordInput,
                                label=("Password"),
                                required=True)
    
    password2 = forms.CharField(widget=forms.PasswordInput,
                                label=("Password (again)"),
                                required=True)

    def clean(self):
        """
        Verifiy that the values entered into the two password fields
        match. Note that an error here will end up in
        ``non_field_errors()`` because it doesn't apply to a single
        field.
        
        """
        cleaned_data = super(ConfirmPasswordForm, self).clean()

        p1 = cleaned_data.get('password1')
        p2 = cleaned_data.get('password2')

        if p1 and p2 and p1 != p2:
            raise forms.ValidationError(("The two password fields didn't match."),
                                            code='invalid')
        return cleaned_data


class RegistrationForm(ConfirmPasswordForm):
    """
    Form for registering a new user account.
    
    Validates that the requested username is not already in use, and
    requires the password to be entered twice to catch typos.
    
    Subclasses should feel free to add any additional validation they
    need, but should avoid defining a ``save()`` method -- the actual
    saving of collected user data is delegated to the active
    registration backend.

    """
    if settings.USE_CAPTCHA:
        captcha = NoReCaptchaField(label='Captcha', 
            error_messages={'required': 'Captcha validation is required.'},
            gtag_attrs={'data-size': 'normal'}
        )
    username = forms.RegexField(
        regex=r'^([\w]+[\s\-_]?)+[\w]+$',
        max_length=30,
        label=("Username"),
        error_messages={
            'invalid': ("This value may contain only letters, "
                "numbers and - _ or space characters.")
        })
    email = forms.EmailField(label=("E-mail"),
                             required=True)
    trial = forms.BooleanField(label=("I want to be a trial user"),
                               required=False)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super(RegistrationForm, self).__init__(*args, **kwargs)
        if settings.USE_CAPTCHA:
            self.fields.keyOrder = [
                'username', 'email', 'password1', 'password2', 
                'captcha', 'trial', 
            ]
        else:
            self.fields.keyOrder = [
                'username', 'email', 'password1', 'password2', 
                'trial', 
            ]
        # Get the number of trial users and disable the field
        # if it exceeds the treshold
        if (len(fiware_api.keystone.get_trial_role_assignments(
                self.request)) 
            >= getattr(settings, 'MAX_TRIAL_USERS', 0)):
            self.fields['trial'].widget.attrs['disabled'] = 'disabled'
            self.fields['trial'].label = mark_safe(
                self.fields['trial'].label + render_to_string(TRIAL_USER_MESSAGE))
    
    # def clean_username(self):
    #     """ Validate that the username is not already in use."""
    #     username = self.cleaned_data['username']

    #     try:
    #         existing = fiware_api.keystone.check_username(username)
    #         raise forms.ValidationError(("A user with that username already exists."),
    #                                     code='invalid')
    #     except keystoneclient_exceptions.NotFound:
    #         return username

    def clean_email(self):
        """ Validate that the email is not already in use and if its banned
        on the black list or allowed in the white list, depending on the settings"""

        email = self.cleaned_data['email']
        domains = email.split('@')[1].split('.')
        email_domain = ".".join(domains[len(domains)-2:len(domains)])
        list_name = getattr(settings, 'EMAIL_LIST_TYPE', None)
        if list_name:
            __location__ = os.path.realpath(
                os.path.join(os.getcwd(), os.path.dirname(__file__)))
            
            f = open(os.path.join(__location__, list_name + '.txt'), 'rb')
            emails = [row.strip() for row in f]

            if list_name == 'blacklist' and email_domain in emails:
                raise forms.ValidationError(
                    "You are using a forbidden e-mail domain in this project.",
                    code='invalid')
            elif list_name == 'whitelist' and email_domain not in emails:
                raise forms.ValidationError(
                    "You are using a forbidden e-mail domain in this project.",
                    code='invalid')
        try:
            existing = fiware_api.keystone.check_email(self.request, email)
            raise forms.ValidationError(("The email is already in use."),
                                         code='invalid')
        except keystoneclient_exceptions.NotFound:
            return email


class EmailForm(forms.Form):
    email = forms.EmailField(label=("E-mail"),
                             required=True)

class SecurityQuestionForm(forms.Form):
    email = forms.CharField(widget = forms.HiddenInput)
    security_answer = forms.CharField(label=("Answer"),
                                 required=True)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        email = kwargs.pop('email', None)
        super(SecurityQuestionForm, self).__init__(*args, **kwargs)
        self.fields['email'].initial = email

    def clean(self):
        cleaned_data = self.cleaned_data

        security_answer = cleaned_data['security_answer']
        email = cleaned_data['email']

        user = fiware_api.keystone.check_email(self.request, email)
        if fiware_api.keystone.two_factor_check_security_question(self.request, user, security_answer):
            fiware_api.keystone.two_factor_disable(self.request, user)
            return cleaned_data
        else:
            raise forms.ValidationError("The answer provided is wrong")

class ChangePasswordForm(ConfirmPasswordForm):
    pass


class LoginWithEmailForm(openstack_auth_forms.Login):
    """Change the label for username field to email and remove
    translations.
    """
    username = forms.CharField(
        label=("Email"),
        widget=forms.TextInput(attrs={"autofocus": "autofocus"}))
    password = forms.CharField(
        label=("Password"),
        widget=forms.PasswordInput(render_value=False))
    