"""
This script consists of all the functions which 
is performing various DB operations
"""

from __future__ import absolute_import
import pam
from . import sql
from oslo_log import log
from keystone.auth.plugins.twofactor import *
from keystone.identity.backends.configuration import *
#from datetime import datetime
import time

###For 2Factor Authentication
import os
import base64
import io
import os
import sys
import math
import hashlib
import hmac
import struct
import base64
###

conf = Config()

# for logging 
LOG = log.getLogger(__name__)

class DbBackend:
    """
    This class contains all the functions for performing 
    necessary querying
    """

   
    def verifyTotp(self, user_totp, userid):
        """To validate the TOTP code entered by the user for enabling 2FA"""
        print "Entering the verify totp function"
        print "USER CHECK"
        
        Identity = sql.Identity(userid)
        user     = Identity.get_user(userid)
	print user
        secret   = user['secret_key']
	print secret
        time_range=30
        i=0
	
        print('generate totp function')

        #Converting the secret key
        secret = base64.b32decode(secret, True)
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
        generated_totp =  "%06d" % code

        #Generate a code form our side using algorithm and use it to validate
        #generated_totp  = self.generate_totp(secret)
	print generated_totp
        #return True
        print user_totp
        print generated_totp
        print 'entering code comparison'
     
        #Code comparison
        if user_totp == generated_totp:
            print "true"
            return True
        else:
  	    print 'falseeeeee'
            return False

    def generate_totp(secret, time_range=30, i=0):
        """Algorithm for generating the Time Based One Time Password.
        Using this function we generate and find the unique TOTP value corresponding to a 
        secret key at the current moment. TOTP values are Time based and valid for only a 
        few seconds.
        Args:
           secret: unique secret key using which we find the current TOTP value
   
        Return:
           The unique TOTP value based on the current time.
        """

        print('generate totp function')

        #Converting the secret key
        secret = base64.b32decode(secret, True)
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

    def get_def_proj_id(self, user_id):
        """
        Function to get the default project id for the user.
        This is needed for successful user authentication
        """
        
        LOG.info("For getting default project ID")
       
        Identity = sql.Identity(user_id)
        project_id_result = Identity.get_def_proj_id_query(user_id)

        if project_id_result:
            project_id = project_id_result[0] 
        return project_id
