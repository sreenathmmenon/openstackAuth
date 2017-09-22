"""
This script constsis of implementation for authenticate OTP
"""

import math
from oslo_config import cfg
from oslo_log import log
import six
from keystone import auth
from keystone.auth.plugins import mapped
from keystone.common import dependency
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model
from keystone.auth.plugins.token import *
from keystone.identity.backends.configuration import *
from keystone.identity.backends.db_functions import *

LOG = log.getLogger(__name__)
CONF = cfg.CONF
conf = Config()
dbBackendObj = DbBackend()

@dependency.requires('federation_api', 'identity_api', 'token_provider_api')
class OTP(auth.AuthMethodHandler):
    """
    For authentication of OTP
    """

    def authenticate(self, context, auth_payload, auth_context):
        """
        Turn a signed request with an access key into a keystone token.
        """
        
        LOG.info("OTP authenticate Function")
        
        # for blocking user to login after 3 invalid attempts       
        if not dbBackendObj.blockUserLogin(auth_context['user_id']):
                raise exception.Unauthorized()
                raise exception.ValidationError(attribute='id',target="otp")
        
        # for verifying the OTP
        if dbBackendObj.selectAndVerifyOtp(auth_payload['otp_value'],auth_context['user_id']) :
                def_proj_id = dbBackendObj.get_def_proj_id(auth_context['user_id'])
                
		if 'X-Auth-Token' in context['headers']:
			auth_context['access_token_id'] = context['headers']['X-Auth-Token']

                tokenObj = Token()
                auth_context['project_id'] = def_proj_id
        else :
                raise exception.Unauthorized()
                raise exception.ValidationError(attribute='id',
                                    target="otp")

    def _get_token_ref(self,id) :
        """
        For getting a Token
        """
        
        LOG.info("inside get token ref")
        
        token_id = id
        response = self.token_provider_api.validate_token(token_id)
        return token_model.KeystoneToken(token_id=token_id,
                                 token_data=response)
