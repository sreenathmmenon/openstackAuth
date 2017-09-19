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

import logging

from django import http
from django.contrib import auth
from django.core import exceptions as django_exceptions
from django.core.urlresolvers import reverse_lazy, reverse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.views.generic.edit import FormView

from openstack_auth import views as auth_views
from openstack_dashboard import fiware_api
from openstack_dashboard.dashboards.idm import utils as idm_utils
from openstack_dashboard.fiware_oauth2 import forms
# from openstack_auth import forms
from openstack_dashboard.fiware_auth import forms as fiware_auth_forms

from horizon import messages


LOG = logging.getLogger('idm_logger')

class AuthorizeView(FormView):
    """ Shows the user info about the application requesting authorization. If its the first
    time (the user has never authorized this application before)
    """
    template_name = 'oauth2/authorize.html'
    form_class = forms.AuthorizeForm
    application_credentials = {}
    success_url = reverse_lazy('horizon:user_home')
    oauth_data = {}

    def dispatch(self, request, *args, **kwargs):
        # Load credentials from the request
        self.application_credentials = self.load_credentials(request)

        if not self.application_credentials['application_id']:
            # if no client_id was found, notify and progress no further
            messages.error(request, 'OUATH2 ERROR: client_id is missing in query_string')
            context = {
                'next':(reverse('fiware_oauth2_authorize') + '?' 
                    + self.request.GET.urlencode()),
                'redirect_field_name': auth.REDIRECT_FIELD_NAME,
            }
            return auth_views.login(
                request, 
                extra_context=context,
                form_class=fiware_auth_forms.LoginWithEmailForm, 
                **kwargs)

        # Get the application details
        try:
            self.application = fiware_api.keystone.application_get(
                request,
                self.application_credentials['application_id'],
                use_idm_account=True)

        except Exception:
            msg = ('Unable to retrieve application.')
            LOG.exception(msg)
            messages.error(request, (msg))
            return redirect('horizon:user_home')

        if request.user.is_authenticated():
            # continue
            return super(AuthorizeView, self).dispatch(request, *args, **kwargs)
        else:
            # redirect to the login page showing some info about the application
            self.application.avatar = idm_utils.get_avatar(
                self.application, 
                'img_medium', idm_utils.DEFAULT_APP_MEDIUM_AVATAR)
            context = {
                'next':(reverse('fiware_oauth2_authorize') + '?' 
                    + self.request.GET.urlencode()),
                'redirect_field_name': auth.REDIRECT_FIELD_NAME,
                'show_application_details':True,
                'application':self.application,
            }

            LOG.debug('OAUTH2: Login page with consumer details')

            return auth_views.login(
                request, 
                extra_context=context,
                form_class=fiware_auth_forms.LoginWithEmailForm, 
                **kwargs)

    def load_credentials(self, request):
        # TODO(garcianavalon) check it's set to code
        credentials = {     
            'response_type': request.GET.get('response_type'),
            'application_id': request.GET.get('client_id'),
            'redirect_uri': request.GET.get('redirect_uri'),
            'state': request.GET.get('state'),
        }
        return credentials

    def _request_authorization(self, request, credentials):
        # forward the request to the keystone server to store the credentials
        try:
            self.oauth_data = \
                fiware_api.keystone.request_authorization_for_application(
                    request,
                    credentials.get('application_id'),
                    credentials.get('redirect_uri'),
                    response_type=credentials.get('response_type'),
                    state=credentials.get('state', None))
        except Exception as e:
            LOG.warning(('OAUTH2: exception when requesting '
                         'authorization %s'), e)
            # TODO(garcianavalon) finner exception handling
            self.oauth_data = {
                'error': e
            }   

    def _already_authorized(self, request, credentials):
        # check if the user already authorized the app for that redirect uri
        app_id = credentials.get('application_id', None)
        if not app_id:
            LOG.debug('OAUTH2: no application_id in credentials')
            return False
        try:
            access_tokens = fiware_api.keystone.get_user_access_tokens(
                request, request.user.id)
            for token in access_tokens: 
                if token.consumer_id == app_id:
                    LOG.debug(('OAUTH2: Application %s already '
                               'authorized'), app_id)
                    return True
            LOG.debug(('OAUTH2: Application %s NOT already' 
                       'authorized'), app_id)
            return False
        except Exception as e:
            LOG.error(('OAUTH2: exception when checking'
                       'access tokens %s'), e)
            # TODO(garcianavalon) finner exception handling
            return False

    def get(self, request, *args, **kwargs):
        """Show a form with info about the scopes and the application to the user"""
        if self.application_credentials:
            self._request_authorization(request, self.application_credentials)
            
            # check if user already authorized this app
            if self._already_authorized(request, self.application_credentials):
                return self.obtain_access_token(request)

            # if not, request authorization from user
            return super(AuthorizeView, self).get(request, *args, **kwargs)
        else:
            LOG.debug('OAUTH2: there is no pending authorization request, redirect to index')
            return redirect('horizon:user_home')

    def get_context_data(self, **kwargs):
        context = super(AuthorizeView, self).get_context_data(**kwargs)
        context['oauth_data'] = self.oauth_data
        context['application_credentials'] = self.application_credentials
        context['application'] = self.application
        context['query_string'] = '?' + self.request.GET.urlencode()
        return context

    def post(self, request, *args, **kwargs):
        # Pass request to get_form
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            # Pass request to form_valid.
            return self.form_valid(request, form)
        else:
            return self.form_invalid(form)

    def form_valid(self, request, form):
        return self.obtain_access_token(request)

    def form_invalid(self, form):
        # NOTE(garcianavalon) there is no case right now where this form would be
        # invalid, because is an empty form. In the future we might use a more complex
        # form (multiple choice scopes for example)
        pass

    def obtain_access_token(self, request):
        try:
            if self.application_credentials.get('response_type', None) == 'code':

                authorization_code = fiware_api.keystone.authorize_application(
                    request,
                    application=self.application_credentials['application_id'])

                LOG.debug('OAUTH2: Authorization Code obtained %s', 
                    authorization_code.code)
                # redirect resource owner to client with the authorization code
                LOG.debug('OAUTH2: Redirecting user back to %s', 
                    authorization_code.redirect_uri)
                
                # NOTE(garcianavalon) to support custom schemes for mobile apps
                # Create custom response to avoid security check in protocol
                res = http.HttpResponse(authorization_code.redirect_uri, status=302)
                res['Location'] = authorization_code.redirect_uri
                return res

            elif self.application_credentials.get('response_type', None) == 'token':
                # Implicit grant
                response = fiware_api.keystone.forward_implicit_grant_authorization_request(
                    request,
                    application_id=self.application_credentials['application_id'])

                # NOTE(garcianavalon) to support custom schemes for mobile apps
                # Create custom response to avoid security check in protocol
                res = http.HttpResponse(
                    response.headers['location'],
                    status=response.status_code)
                res['Location'] = response.headers['location']
                res.reason_phrase = response.reason
                return res

        except Exception as e:
            LOG.error('OAUTH2: exception when authorizing %s', e)
            msg = (('An error occurred when trying to obtain' 
                    'the authorization code.'))
            messages.error(request, (msg))
            return redirect('horizon:user_home')
        

def cancel_authorize(request, **kwargs):
    LOG.debug('OAUTH2: authorization request dennied, redirect to home')
    return redirect('horizon:user_home')


class AccessTokenView(View):
    """ Handles the access token request form the clients (applications). Forwards the 
    request to the Keystone backend.
    """
    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super(AccessTokenView, self).dispatch(request, *args, **kwargs)
   
    def post(self, request, *args, **kwargs):
        # NOTE(garcianavalon) Instead of using the client we simply redirect the request 
        # because is simpler than extracting all the data to make the exact same request 
        # again from it
        LOG.debug('OAUTH2: forwading the access_token request')
        try:
            response = fiware_api.keystone.forward_access_token_request(request)
            return http.HttpResponse(
                content=response.content, 
                content_type=response.headers['content-type'], 
                status=response.status_code, 
                reason=response.reason)
        except django_exceptions.PermissionDenied:
            return http.HttpResponseBadRequest(
                content='Authentication header missing. Use HTTP Basic.')
        


class UserInfoView(View):
    """ Forwards to the Keystone backend the validate token request (access the user info).
    """

    def get(self, request, *args, **kwargs):
        # NOTE(garcianavalon) Instead of using the client we simply redirect the request 
        # because is simpler than extracting all the data to make the exact same request 
        # again from it
        LOG.debug('OAUTH2: forwading the user info (validate token) request')
        response = fiware_api.keystone.forward_validate_token_request(request)
        return http.HttpResponse(content=response.content, 
                            content_type=response.headers['content-type'], 
                            status=response.status_code, 
                            reason=response.reason)