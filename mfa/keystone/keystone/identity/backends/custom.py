"""
Script for implementation of doing authentication(overriding default),
For password checking , validation , blocking user login,
Generating Twilio SMS
"""

from __future__ import absolute_import
import pam
from . import sql
from oslo_log import log
from keystone.auth.plugins.twofactor import TwoFactor
from keystone.identity.backends.configuration import *
from keystone.identity.backends.db_functions import *
import json

conf = Config()
db = conf.getDBConnection()
cursor = db.cursor()

# for logging 
LOG = log.getLogger(__name__)
dbBackendObj = DbBackend()

class Identity(sql.Identity):
    """
    Custom Identity class for overriding default authentication.
    """
    
    LOG.info("Inside class Identity -custom.py file")

    """
    # for checking password and validation
    def _check_password(self, password, user_ref):
        #""
        #For password checking and validation,
        #Blocking the users from logging in,
        #Generating a message to mobile number
        #""

        LOG.info('check password function')
        # for getting necessary field values
        username = user_ref.get('name')
	user_extra = ''
	user_extra = user_ref.get('extra')
	LOG.info(user_ref.__dict__)
	LOG.info(type(user_ref.get('extra')))

	extra= user_ref.get('extra')
	two_factor_enabled = extra.get("two_factor_enabled", 0)
	
	LOG.info('two factor check')
	LOG.info(two_factor_enabled)

	LOG.info('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%5')
	#Fetching the user related details
        userid = user_ref.get('id')

	print type(two_factor_enabled)
	#two_factor_enabled = bool(0)
        #Converting to bool to fix errors
        if type(two_factor_enabled) == unicode:
            print "Entering the loop sinc etype is unicode"
            two_factor_enabled = self.str2bool(two_factor_enabled)

	#two_factor_enabled = self.str2bool(two_factor_enabled)
	LOG.info(two_factor_enabled)
	LOG.info('newwww')
	print type(two_factor_enabled)

	if two_factor_enabled:
	   print "enabledd entering"
	else:
	   print "not enteringg"

	#print(treee)
	if two_factor_enabled:
	  LOG.info('Entering sicne two factor is enabled')
	  LOG.info(two_factor_enabled)

          #return True
          LOG.info('check password function')
          
          userid = user_ref.get('id')
          return True 
          #To block the user login
          #dbBackendObj.blockUserLogin(userid)

        else:
          LOG.info('two factor authentication is not enabled')
          if super(Identity, self)._check_password(password, user_ref):
              LOG.info('after super -true')
	      return True
	  else:
	      LOG.info('after super-false')
	      return False
    """

    def str2bool(self, v):
	LOG.info('Entering conversion function')
        return v.lower() in ("yes", "true", "t", "1") 
