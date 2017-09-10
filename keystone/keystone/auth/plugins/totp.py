"""
Script contains the implementation details for TOTP
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

LOG          = log.getLogger(__name__)
CONF         = cfg.CONF
conf         = Config()
dbBackendObj = DbBackend() 


class TOTP(auth.AuthMethodHandler):
    """
    For authentication of TOTP
    """
    def authenticate():
        """
        Turn a signed request with access key into a keystone token
        """
        LOG.info('TOTP authenticate function')

        # for blocking user to login after 3 invalid attempts       
        if not dbBackendObj.blockUserLogin(auth_context['user_id']):
                raise exception.Unauthorized()
                raise exception.ValidationError(attribute='id',target="totp")

        # for verifying the TOTP
        if dbBackendObj.selectAndVerifyOtp(auth_payload['totp_value'],auth_context['user_id']):
                def_proj_id = dbBackendObj.get_def_proj_id(auth_context['user_id'])
                
		if 'X-Auth-Token' in context['headers']:
			auth_context['access_token_id'] = context['headers']['X-Auth-Token']

                tokenObj = Token()
                auth_context['project_id'] = def_proj_id
        else :
                raise exception.Unauthorized()
                raise exception.ValidationError(attribute='id',
                                    target="totp")

    def _get_token_ref():
        """
        For getting the token
        """
        LOG.info("inside get token ref")
        
        token_id = id
        response = self.token_provider_api.validate_token(token_id)
        return token_model.KeystoneToken(token_id=token_id,
                                 token_data=response)

