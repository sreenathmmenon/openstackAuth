# Copyright (C) 2015 Universidad Politecnica de Madrid
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

from django.core.urlresolvers import reverse_lazy
from django.contrib.auth.decorators import login_required  # noqa
from django.shortcuts import redirect
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView

from keystoneclient import exceptions as ks_exceptions

from horizon import messages
from horizon import exceptions

from openstack_auth import views as openstack_auth_views

from openstack_dashboard import fiware_api
from openstack_dashboard.fiware_auth import forms as fiware_forms
from openstack_dashboard.utils import email as email_utils


LOG = logging.getLogger('idm_logger')


class _RequestPassingFormView(FormView):
    """
    A version of FormView which passes extra arguments to certain
    methods, notably passing the HTTP request nearly everywhere, to
    enable finer-grained processing.
    
    """
    def post(self, request, *args, **kwargs):
        # Pass request to get_form_class and get_form for per-request
        # form control.
        form_class = self.get_form_class(request)
        form = self.get_form(form_class)
        if form.is_valid():
            # Pass request to form_valid.
            return self.form_valid(request, form)
        else:
            return self.form_invalid(form)

    def get_form_class(self, request=None):
        return super(_RequestPassingFormView, self).get_form_class()

    def get_form_kwargs(self, request=None, form_class=None):
        return super(_RequestPassingFormView, self).get_form_kwargs()

    def get_initial(self, request=None):
        return super(_RequestPassingFormView, self).get_initial()

    def get_success_url(self, request=None, user=None):
        # We need to be able to use the request and the new user when
        # constructing success_url.
        return super(_RequestPassingFormView, self).get_success_url()

    def form_valid(self, form, request=None):
        return super(_RequestPassingFormView, self).form_valid(form)

    def form_invalid(self, form, request=None):
        return super(_RequestPassingFormView, self).form_invalid(form)


class RegistrationView(_RequestPassingFormView):
    """Creates a new user in the backend. Then redirects to the log-in page.
    Once registered, defines the URL where to redirect for activation
    """
    form_class = fiware_forms.RegistrationForm
    http_method_names = ['get', 'post', 'head', 'options', 'trace']
    success_url = reverse_lazy('login')
    template_name = 'auth/registration/registration.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.username:
            return redirect('horizon:user_home')
        return super(RegistrationView, self).dispatch(request, *args, **kwargs)
    
    def get_form_kwargs(self, request=None, form_class=None):
        kwargs = super(RegistrationView, self).get_form_kwargs()
        kwargs['request'] = request
        return kwargs
        
    def form_valid(self, request, form):
        new_user = self.register(request, **form.cleaned_data)
        
        if new_user:
            success_url = self.get_success_url(request, new_user)
            # success_url must be a simple string, no tuples
            return redirect(success_url)
        
        return redirect('fiware_auth_register')

    # We have to protect the entire "cleaned_data" dict because it contains the
    # password and confirm_password strings.
    def register(self, request, **cleaned_data):
        LOG.info('Singup user %s.', cleaned_data['username'])
        # delegate to the manager to create all the stuff
        try:
            new_user = fiware_api.keystone.register_user(
                request,
                name=cleaned_data['email'],
                password=cleaned_data['password1'],
                username=cleaned_data['username'])
            LOG.debug('user %s created.', 
                cleaned_data['username'])

            # Grant trial or basic role in the domain
            if cleaned_data['trial']:
                fiware_api.keystone.update_to_trial(
                    request, new_user.id)
            else:
                fiware_api.keystone.update_to_basic(
                    request, new_user.id)

            # Grant purchaser to user's cloud organization in all 
            # default apps. If trial requested, also in Cloud
            default_apps = fiware_api.keystone.get_fiware_default_apps(request)

            if cleaned_data['trial']:
                cloud_app = fiware_api.keystone.get_fiware_cloud_app(
                    request, use_idm_account=True)
                default_apps.append(cloud_app)

            purchaser = fiware_api.keystone.get_purchaser_role(
                request, use_idm_account=True)

            for app in default_apps:
                fiware_api.keystone.add_role_to_organization(
                    request, 
                    role=purchaser, 
                    organization=new_user.cloud_project_id,
                    application=app.id, 
                    use_idm_account=True)
                LOG.debug('Granted purchaser to org %s in app %s',
                          new_user.cloud_project_id,
                          app.id)    

            # Grant a public role in cloud app to user in his/her
            # cloud organization if trial requested
            # and activate the Spain2 region
            if cleaned_data['trial']:
                default_cloud_role = \
                    fiware_api.keystone.get_default_cloud_role(
                        request, cloud_app, use_idm_account=True)

                if default_cloud_role:
                    fiware_api.keystone.add_role_to_user(
                        request,
                        role=default_cloud_role.id,
                        user=new_user.id,
                        organization=new_user.cloud_project_id,
                        application=cloud_app.id,
                        use_idm_account=True)
                    LOG.debug('granted default cloud role')
                else:
                    LOG.debug('default cloud role not found')

                # TODO(garcianavalon) as setting!
                region_id = 'Spain2'
                endpoint_groups = fiware_api.keystone.endpoint_group_list(
                    request, use_idm_account=True)
                region_group = next(
                    group for group in endpoint_groups
                    if group.filters.get('region_id', None) == region_id
                )

                if not region_group:
                    messages.error(
                        request, 'There is no endpoint group defined for that region')
                    return

                fiware_api.keystone.add_endpoint_group_to_project(
                    request,
                    project=new_user.cloud_project_id,
                    endpoint_group=region_group,
                    use_idm_account=True)

            email_utils.send_activation_email(new_user, new_user.activation_key)

            msg = (
                'Account created succesfully, check your email for'
                ' the confirmation link.'
            )
            messages.success(request, msg)
            return new_user

        except Exception as e:
            LOG.warning(e)
            messages.error(request, 'Unable to create user, please try again later.')
    
class ActivationView(TemplateView):
    http_method_names = ['get']
    template_name = 'auth/activation/activate.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.username:
            return redirect('horizon:user_home')
        return super(ActivationView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        activated_user = self.activate(request, *args, **kwargs)
        if activated_user:
            return redirect(self.success_url)
        return super(ActivationView, self).get(request, *args, **kwargs)

    def activate(self, request):
        activation_key = request.GET.get('activation_key')
        user = request.GET.get('user')
        LOG.info('Requested activation for key %s.', activation_key)
        try:
            activated_user = fiware_api.keystone.activate_user(
                request, user, activation_key)
            LOG.debug('user %s was successfully activated.', 
                      activated_user.username)
            messages.success(request, 
                             ('User "%s" was successfully activated.') 
                             %activated_user.username)
            return activated_user
        except Exception:
            msg = ('Unable to activate user.')
            LOG.warning(msg)
            exceptions.handle(request, msg)

class RequestPasswordResetView(_RequestPassingFormView):
    form_class = fiware_forms.EmailForm
    template_name = 'auth/password/request.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.username:
            return redirect('horizon:user_home')
        return super(RequestPasswordResetView, self).dispatch(
            request, *args, **kwargs)

    def form_valid(self, request, form):
        success = self._create_reset_password_token(request, 
            form.cleaned_data['email'])
        if success:
            return super(RequestPasswordResetView, self).form_valid(form)
        else:
            return self.get(request) # redirect to itself

    def _create_reset_password_token(self, request, email):
        LOG.info('Creating reset token for %s.', email)
        try:
            user = fiware_api.keystone.check_email(request, email)

            if not user.enabled:
                msg = ('The email address you have specified is registered but not '
                    'activated. Please check your email for the activation link '
                    'or request a new one. If your problem '
                    'persits, please contact fiware-lab-help@lists.fiware.org')
                messages.error(request, msg)
                return False
                
            reset_password_token = fiware_api.keystone.get_reset_token(request, user)
            token = reset_password_token.id
            user = reset_password_token.user
            email_utils.send_reset_email(email, token, user)
            messages.success(request, ('Reset email send to %s') % email)
            return True

        except ks_exceptions.NotFound:
            LOG.debug('email address %s is not registered', email)
            msg = ('Sorry. You have specified an email address that is not '
                'registered to any of our user accounts. If your problem '
                'persits, please contact: fiware-lab-help@lists.fiware.org')
            messages.error(request, msg)

        except Exception as e:
            msg = ('An error occurred, try again later.')
            messages.error(request, msg)
            
        return False


class ResetPasswordView(_RequestPassingFormView):
    form_class = fiware_forms.ChangePasswordForm
    template_name = 'auth/password/reset.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.username:
            return redirect('horizon:user_home')
        self.token = request.GET.get('token')
        self.email = request.GET.get('email')
        return super(ResetPasswordView, self).dispatch(
            request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super(ResetPasswordView, self).get_context_data(**kwargs)
        context['token'] = self.token
        context['email'] = self.email
        return context

    def form_valid(self, request, form):
        password = form.cleaned_data['password1']
        token = self.token
        user = self._reset_password(request, token, password)
        if user:
            return super(ResetPasswordView, self).form_valid(form)
        return self.get(request) # redirect to itself

    def _reset_password(self, request, token, password):
        LOG.info('Reseting password for token {0}.'.format(token))
        user_email = self.email
        try:
            user = fiware_api.keystone.check_email(request, user_email)
            user = fiware_api.keystone.reset_password(request, user, token, password)
            if user:
                messages.success(request, ('password successfully changed.'))
                return user
        except Exception:
            msg = ('Unable to change password.')
            LOG.warning(msg)
            exceptions.handle(request, msg)
        return None

class ResendConfirmationInstructionsView(_RequestPassingFormView):
    form_class = fiware_forms.EmailForm
    template_name = 'auth/registration/confirmation.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.username:
            return redirect('horizon:user_home')
        return super(ResendConfirmationInstructionsView, self).dispatch(
            request, *args, **kwargs)

    def form_valid(self, request, form):
        success = self._resend_confirmation_email(request, 
            form.cleaned_data['email'])
        if success:
            return super(ResendConfirmationInstructionsView, self).form_valid(form)
        else:
            return self.get(request) # redirect to itself
            
    def _resend_confirmation_email(self, request, email):
        try:
            user = fiware_api.keystone.check_email(request, email)

            if user.enabled:
                msg = ('Email was already confirmed, please try signing in')
                LOG.debug('email address %s was already confirmed', email)
                messages.error(request, msg)
                return False

            activation_key = fiware_api.keystone.new_activation_key(request, user)

            email_utils.send_activation_email(user, activation_key.id)
            msg = ('Resended confirmation instructions to %s') %email
            messages.success(request, msg)
            return True

        except ks_exceptions.NotFound:
            LOG.debug('email address %s is not registered', email)
            msg = ('Sorry. You have specified an email address that is not '
                'registered to any our our user accounts. If your problem '
                'persits, please contact: fiware-lab-help@lists.fiware.org')
            messages.error(request, msg)

        except Exception:
            msg = ('An error occurred, try again later.')
            messages.error(request, msg)
        
        return False


class TwoFactorLostAppView(_RequestPassingFormView):
    form_class = fiware_forms.EmailForm
    template_name = 'auth/two_factor/lost_app.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.username:
            return redirect('horizon:user_home')
        return super(TwoFactorLostAppView, self).dispatch(
            request, *args, **kwargs)

    def get_success_url(self):
        succ_url = reverse_lazy('fiware_two_factor_sec_question') + '?email=' + self.email
        return succ_url

    def form_valid(self, request, form):
        self.email = form.cleaned_data['email']
        return super(TwoFactorLostAppView, self).form_valid(form)

class TwoFactorSecurityQuestionView(_RequestPassingFormView):
    form_class = fiware_forms.SecurityQuestionForm
    template_name = 'auth/two_factor/security_question.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        if request.GET:
            try:
                email = request.GET.get('email')
                self.user = fiware_api.keystone.check_email(request, email)
                if fiware_api.keystone.two_factor_is_enabled(request, self.user):
                    return super(TwoFactorSecurityQuestionView, self).dispatch(request, *args, **kwargs)
                else:
                    LOG.debug('email address %s has not two factor enabled', email)
                    msg = ('Sorry. You have specified an email address that has not two '
                        'factor enabled. If your problem '
                        'persits, please contact: fiware-lab-help@lists.fiware.org')
                    messages.error(request, msg)
                    return redirect(self.success_url)
            except ks_exceptions.NotFound:
                LOG.debug('email address %s is not registered', email)
                msg = ('Sorry. You have specified an email address that is not '
                    'registered to any of our user accounts. If your problem '
                    'persits, please contact: fiware-lab-help@lists.fiware.org')
                messages.error(request, msg)
                return redirect(self.success_url)
        else:
            self.user = fiware_api.keystone.check_email(request, request.POST.get('email', None))
            return super(TwoFactorSecurityQuestionView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(TwoFactorSecurityQuestionView, self).get_context_data(**kwargs)
        context['security_question'] = fiware_api.keystone.\
                                       two_factor_get_security_question(self.request, self.user)

        return context

    def get_form_kwargs(self, request=None, form_class=None):
        kwargs = super(TwoFactorSecurityQuestionView, self).get_form_kwargs()
        kwargs['request'] = request
        kwargs['email'] = self.request.GET.get('email', None)
        return kwargs

    def form_valid(self, request, form):
        msg = ("Two factor has been disabled for your account. Now you can log in with your password again.")
        messages.success(self.request, msg)
        return super(TwoFactorSecurityQuestionView, self).form_valid(form)

class TwoFactorForgotAnswerView(TemplateView):
    template_name = 'auth/two_factor/_forgot_answer.html'

    def get_context_data(self, **kwargs):
        return {'hide': True}

@login_required
def switch(request, tenant_id, **kwargs):
    """Wrapper for ``openstack_auth.views.switch`` to add a message
    for the user.
    """
    user_organization = request.user.default_project_id
    response = openstack_auth_views.switch(request, tenant_id, **kwargs)
    if tenant_id != user_organization:
        organization_name = next(o.name for o in request.organizations 
                         if o.id == tenant_id)
        msg = ("Your identity has changed. Now you are acting on behalf "
               "of the \"{0}\" organization. Use the top-right menu to " 
               "regain your identity as individual user.").format(
               organization_name)
        messages.info(request, msg)
    return response

