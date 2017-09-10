"""
Script for implementation of doing authentication(overriding default),
For password checking , validation , blocking user login,
Generating Twilio SMS
"""

from __future__ import absolute_import
import pam
from . import sql
#from twilio.rest import TwilioRestClient
from twilio.rest import Client
from oslo_log import log
from keystone.auth.plugins.otp import OTP
from keystone.auth.plugins.totp import TOTP
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
    
    LOG.info("Inside class Identity")

    # for checking password and validation
    def _check_password(self, password, user_ref):
        """
        For password checking and validation,
        Blocking the users from logging in,
        Generating a message to mobile number
        """

	TWO_FACTOR_ENABLED = False

        LOG.info('check password function')
        # for getting necessary field values
        username = user_ref.get('name')
        #extra = user_ref.get('extra')
        tPhone = '+919496341531'
        fPhone = '+16306569833'
	user_extra = ''
	user_extra = user_ref.get('extra')
	LOG.info(user_ref.__dict__)
	LOG.info(type(user_ref.get('extra')))
	extra= user_ref.get('extra')
	#two_factor_enabled = False
	two_factor_enabled = extra.get("two_factor_enabled", 0)
	
	LOG.info('two factor check')
	LOG.info(two_factor_enabled)

	LOG.info('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%5')
	#Fetching the user related details
        userid = user_ref.get('id')

	"""
        #two_factor_enabled = user_ref.get('extra')['two_factor_enabled']
	user_extra_data =  json.dumps(user_ref.get('extra'))
	LOG.info(user_extra_data)
	extra_data_converted = json.loads(user_extra_data)
	LOG.info(extra_data_converted)
	 
	two_factor_enabled = extra_data_converted['two_factor_enabled']
	LOG.info(two_factor_enabled)
	    
	LOG.info('two_factor_enabled value is ')
	LOG.info(two_factor_enabled)

        LOG.info('Entering check_password function - custom.py file')

        LOG.info('%%%%%%%%%%%%%%%%%%%%%%%%%%%%5')
        LOG.info(user_ref)
	LOG.info(user_ref.__dict__)
        LOG.info('%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
	#LOG.info(user_ref.get('extra')['email'])
	"""
	print type(two_factor_enabled)
	#two_factor_enabled = bool(0)
	two_factor_enabled = self.str2bool(two_factor_enabled)
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
          
          #To block the user login
          dbBackendObj.blockUserLogin(userid)

          # Check if the current auth works, if yes, go for the OTP generation.
          if super(Identity, self)._check_password(password, user_ref):

                # if user is listed in failedusers table and needs to be blocked
                if not  dbBackendObj.blockUserLogin(userid):
                        return False
                    
                # on successful login cleartabledatas(failed details)
                else:
                        dbBackendObj.clearTableDataOnSuccess(userid)

                # if phone field exists
                #if 'phone' in extra  :
                if tPhone:

                        LOG.info('Entering the loop since phone number is present')

                        # twilio authentication details
                        account_sid = twilio_account_sid
                        auth_token  = twilio_auth_token
                        #client = TwilioRestClient(account_sid, auth_token)
                        client = Client(account_sid, auth_token)
                        otp = None
                        #toPhone = extra['phone']
                        toPhone  = tPhone

			import datetime
			import time

	                last_otp_time = ''
		        total_row_otp = ''
			savedTime = 0
			diff_sec = 0
		        otp_time_limit = '60'
			time_format = '%Y-%m-%d %H:%M:%S'
		
		        current = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		        new_current = datetime.datetime.strptime(current, time_format) 	
			
			idObj = sql.Identity(userid)

			#Find the time of last generated OTP
    	                savedOtpResult = idObj.selectOTP(userid)
                        if savedOtpResult:
                            savedTime = savedOtpResult[1]
			    LOG.info(savedTime)
			    LOG.info(type(savedTime))
                            #savedTime = datetime.datetime.strptime(savedTime, time_format)
 			    LOG.info('Types are:')
		     	    LOG.info(type(new_current))
	                    diff = new_current - savedTime
			    diff_sec = diff.total_seconds()
			    LOG.info('Time difference is ')
			    LOG.info(diff_sec)

                	if (diff_sec == 0) or (diff_sec > 180):
			    #calling otp generate function
                            otp = self.generateOTP()
                            print(otp)
                            LOG.info('OTP value is ')
                            LOG.info(otp)

                            # for inserting otp in table
                            dbBackendObj.insertOtp(otp,userid)

                            # For sending SMS to user with OTP values
                            smsText = "Your OTP for openstack login is :" + str(otp)
                            #sms = client.sms.messages.create(body="Your OTP for openstack login is :" + str(otp) , to=toPhone, from_=str(twilio_from))
                            message = client.messages.create(to=toPhone, from_=fPhone, body=smsText)
                        
                            # If sms sent, return true, else false.
                            if(message.sid) :
                                LOG.info(message)
                                return True
                            else :
                                return False
			else:
			    #If returning to the page for second time after a successful otp generation
			    return True
                else :
                        return False

        else:
          LOG.info('two factor authentication is not enabled')
          if super(Identity, self)._check_password(password, user_ref):
              LOG.info('after super -true')
	      return True
	  else:
	      LOG.info('after super-false')
	      return False

    def str2bool(self, v):
	LOG.info('Entering conversion function')
        return v.lower() in ("yes", "true", "t", "1") 

    # function for generating OTP
    def generateOTP(self) :
        """
        Function to generate OTP
        """
        
        LOG.info("Inside Generate OTP function")
        
        import pyotp
        totp = pyotp.TOTP('base32secret3232')
        optVal = totp.now()
        return optVal
