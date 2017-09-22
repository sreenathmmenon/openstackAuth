"""
This script consists of all the functions which 
is performing various DB operations
"""

from __future__ import absolute_import
import pam
from . import sql
from twilio.rest import TwilioRestClient
from oslo_log import log
from keystone.auth.plugins.otp import *
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

    def insertOtp(self, otp, userid) :
        """
        Function for inserting OTP in to table keystone.otp 
        for validation purpose. OTP will be inserted into
        table on successful login with Username and 
        Password
        """
        
        LOG.info("Inside insert OTP function, for inserting OTP value in table")
        
        # for datetime operations
        import datetime
        
        # for formatting the date and time as needed
        time_format = '%Y-%m-%d %H:%M:%S'
	total_row_otp = ''
	
        current = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_current = datetime.datetime.strptime(current, time_format)

        # selecting count of userid from table for inseting into table
        Identity = sql.Identity(userid)

        total_row_otp_result = Identity.otpCountQuery(userid)
        total_row_otp = total_row_otp_result[0]

        # If OTP entry already exists update the field value
        if total_row_otp:

            Identity = sql.Identity(userid)
            updateOtp = Identity.updateOtpQuery(userid, otp)
        # if no OTP entry exists Insert new row in it
        else:
            Identity = sql.Identity(userid)
            inserOtp = Identity.insertOtpQuery(userid, otp)
        return True

    def blockUserLogin(self, userid):      
        """
        Function to decide whether user is blocked.
        During login, checks whether the user is blocked by 
        checking user entry in faileduser table in keystone DB. 
        If yes , then time difference(between current and blocked time) is less than 24 hours
        then it will block user from logging in. else it will allow
        user to log in.
        """

        LOG.info("Inside blockuserlogin function, for fetching the details for blocking user")

        time_user_blocked = None
        Identity = sql.Identity(userid)
        time_user_blocked_result = Identity.userFailedTimeQuery(userid)

        if time_user_blocked_result:
            time_user_blocked = time_user_blocked_result[0]

        # when user blocked time exists
        if time_user_blocked:

            # for datetime operations
            import datetime
            import math

            # for formatting the date and time as needed
            f = '%Y-%m-%d %H:%M:%S'
            current = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            new_current = datetime.datetime.strptime(current, f)
            hoursdiffseconds = 0
            hoursdiffseconds = math.floor(((new_current - time_user_blocked).total_seconds()))

            # if difference between current time and block time is less than 24 hours
            if hoursdiffseconds < 86400:
                return False
        return True
   
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

    def selectAndVerifyOtp(self, otp, userid) :
        """
        Function for selecting OTP from DB table for authentication.
        It will select The OTP from table(keystone.otp) 
        and decides the action by comparing it with that of submitted otp.
        Also checks whether OTP is expired using the defined time limit.
        """
        
        LOG.info("Check the submitted OTP with the one saved in DB")

        result = None
        userSubmittedOtp = otp
        
        # for datetime operations
        import datetime

        # for formatting the date and time as needed
        f = '%Y-%m-%d %H:%M:%S'
        current = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_current = datetime.datetime.strptime(current, f)

        Identity = sql.Identity(userid)
        savedOtpResult = Identity.selectOTP(userid)

        if savedOtpResult:

            savedOtp = savedOtpResult[0]
            savedTime = savedOtpResult[1]

        diff = new_current - savedTime
        LOG.info(diff.total_seconds())
        LOG.info(authTimeoutDuration)

        # when totlal difference is greater than authtimeout duration
        if diff.total_seconds() > authTimeoutDuration:
            LOG.info("OTP authentication timed out")

            # for adding data to table on OTP expired case
            self.saveFailedData(userid) 
            raise exception.Unauthorized()

        # If user submitted OTP and OTP from DB matches, user will authenticated.
        LOG.info(savedOtp)
        LOG.info(userSubmittedOtp)
        
        # If cubmitted OTP and OTP from DB matches
        if str(savedOtp).__eq__(str(userSubmittedOtp)) :
            LOG.info("OTPs matching, authentication success.")
            self.clearTableDataOnSuccess(userid)
            return True

        # Submitted OTP and OTP from DB doesn't match
        else :
            LOG.info("OTPs NOT matching, authentication failure.")
            self.saveFailedData(userid)
            raise exception.Unauthorized()
            raise exception.ValidationError(attribute='id',
                                    target="otp")
            return False


    def clearTableDataOnSuccess(self, userid):
        """
        Flushing Table data on Successful Login.
        When user is logging in correctly all the failed data from table for
        particular user will be flushed (keystone.failedusers, faillogin).
        That will be executed after succesful OTP authentication 
        or after succesful login with username and password(after lockout period). 
        """ 
        LOG.info("Clear table data on sucess, for clearing table data on successful attepmt")

        # for getting the total count of failed attempts for user in user login table
        Identity = sql.Identity(userid)
        fail_login_result = Identity.failLoginCountQuery(userid)
        total_rows_userfail = fail_login_result[0]

        if total_rows_userfail:

            # deleting users details from faillogin table
            Identity = sql.Identity(userid)
            deleteFaillog = Identity.deleteFailLogins(userid)

        # for getting the total count of failedusers attempts for user in faileduser table
        Identity = sql.Identity(userid)
        fail_users_result = Identity.failedUsersCountQuery(userid)
        failed_users_count = fail_users_result[0]

        if failed_users_count:

            # deleting users details from failusers table
            Identity = sql.Identity(userid)
            deleteFaillog = Identity.deleteFailUsers(userid)

    def saveFailedData(self, userid) :
        """
        For saving failed data in tables on Wrong OTP attempts.
        When user is entering the wrong OTP each attempts will be entered into keystone DB.
        When user is Attempting wrong OTP, for first two attempts, it will be 
        entered into faillogin table.
        During 3rd wrong attempt user entry will be added into failedusers
        table, which has all users who are locked out.
        When the locked out period is over(ie 24hrs for us) users details will be 
        deleted from table (during the next successful login), and allows the further logins.
        """

        LOG.info("For saving failed data")

        # for datetime operations
        import datetime

        # for formatting the date and time as needed
        f = '%Y-%m-%d %H:%M:%S'
        current = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_current = datetime.datetime.strptime(current, f)

        # for getting the total count of failed attempts for user in user login table
        Identity = sql.Identity(userid)
        fail_login_result = Identity.failLoginCountQuery(userid)
        total_rows_userfail = fail_login_result[0]

        # for getting the failed user last attempt time
        Identity = sql.Identity(userid)
        failedUsersCount = Identity.userFailedTimeQuery(userid)
        hoursdiffseconds = 0

        # last time exists
        if failedUsersCount:
            lasttime_res = failedUsersCount[0]

            # calculating difference
            hoursdiffseconds = math.floor(((new_current - lasttime_res).total_seconds()))

        # difference greater than 24 hours then delete all the entries for user
        if hoursdiffseconds > 86400 :

            # for getting the total count of failed attempts for user in user login table
            Identity = sql.Identity(userid)
            fail_login_result = Identity.failLoginCountQuery(userid)
            total_rows_userfail = fail_login_result[0]

            if total_rows_userfail:

                # deleting users details from faillogin table
                Identity = sql.Identity(userid)
                deleteFaillog = Identity.deleteFailLogins(userid)

                # for getting the total count of failedusers attempts for user in faileduser table
                Identity = sql.Identity(userid)
                fail_users_result = Identity.failedUsersCountQuery(userid)
                failed_users_count = fail_users_result[0]

                if failed_users_count:

                    # deleting users details from failusers table
                    Identity = sql.Identity(userid)
                    deleteFaillog = Identity.deleteFailUsers(userid)
    
                    # insert in to fail login
                    Identity = sql.Identity(userid)
                    insertFailLogin = Identity.insertFailLoginQuery(userid)

        # else part if there is no time difference greater than 24 hours        
        else:

            # until 2 attempts of user trying with wrong otp
            if total_rows_userfail < 2 :
    
                # inserting record in to faillogin table     
                Identity = sql.Identity(userid)
                insertFailLogin = Identity.insertFailLoginQuery(userid)


            # greater than 2 wrong attempts             
            else:            
    
                # number of failed attempts by user
                dentity = sql.Identity(userid)
                count_fail_usertable_result = Identity.failedUsersCountQuery(userid)
                
                if count_fail_usertable_result:
                    countfailusertable = count_fail_usertable_result[0]

                # if entry is already there no need to enter again
                if countfailusertable:   
                    return 0
    
                # if no entry have to insert now
                else:
                    # for inserting details in faileduser table(uesrs needs to be blocked)        
                    Identity = sql.Identity(userid)
                    insertFailUser = Identity.insertFailUserQuery(userid)


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

