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

from django.core import mail
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string

from openstack_dashboard.local import local_settings


LOG = logging.getLogger('idm_logger') 


def send_html_email(recipients, subject, text_template, html_template,
                    from_email=None, content=None):
    LOG.debug('Sending email to %s with subject %s', recipients, subject)
    text_content = render_to_string(text_template, dictionary=content)
    html_content = render_to_string(html_template, dictionary=content)
    
    msg = mail.EmailMultiAlternatives(
        subject=getattr(local_settings, 'EMAIL_SUBJECT_PREFIX', '') + ' ' + subject,
        body=text_content,
        from_email=from_email,
        bcc=recipients,
        connection=mail.get_connection(fail_silently=True))

    msg.attach_alternative(html_content, "text/html")
    msg.send()
    
def send_account_status_expire_email(user, content):
    send_html_email(
        subject='Current Acount Status about to expire',
        recipients=[user.name],
        text_template='email/account_status_expire.txt',
        html_template='email/account_status_expire.html',
        content=content)

def send_account_status_change_email(user, content):
    send_html_email(
        subject='Changed account status',
        recipients=[user.name],
        text_template='email/account_status_change.txt',
        html_template='email/account_status_change.html',
        content=content)

def send_massive_email(recipients, data):
    send_html_email(
        subject=data['subject'], 
        recipients=recipients, 
        text_template='email/massive_email.txt',
        html_template='email/massive_email.html',
        content={
            'html':data['body'],
            'text':data['body'],
        })

def send_activation_email(user, activation_key):
    content = {
        'activation_url':('{0}/activate/?activation_key={1}&user={2}'
            '').format(_get_current_domain(), activation_key, user.id),
        'user':user,
    }

    send_html_email(
        recipients=[user.name],
        subject='Welcome to FIWARE',
        text_template='email/activation.txt',
        html_template='email/activation.html',
        content=content)

def send_reset_email(email, token, user):
    content = {
        'reset_url':('{0}/password/reset/?token={1}&email={2}'
            '').format(_get_current_domain(), token, email),
        'user':user,
    }

    send_html_email(
        recipients=[email], 
        subject='Reset password instructions',
        text_template='email/reset_password.txt',
        html_template='email/reset_password.html',
        content=content)


def send_verification_email(user, key, new_email):
    query_string = '?verification_key={0}&new_email={1}'.format(key, new_email)
    url = _get_current_domain() + reverse('horizon:settings:multisettings:useremail_verify') + query_string
    content = {
        'url': url,
        'user':user,
    }

    send_html_email(
        recipients=[new_email], 
        subject='Account email change requested',
        text_template='email/verify_email.txt',
        html_template='email/verify_email.html',
        content=content)

        
def _get_current_domain():
    if getattr(local_settings, 'EMAIL_URL', None):
        return local_settings.EMAIL_URL
    else:
        LOG.warning(
            'EMAIL_URL not found in local_settings.py. Using fallback value.')
        return 'http://localhost:8000'
