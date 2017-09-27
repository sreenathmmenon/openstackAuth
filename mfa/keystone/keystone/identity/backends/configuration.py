"""
DB configuration,Twilio setup, OTP timeout setup 
"""

from ConfigParser import SafeConfigParser

#Change the following to your match your server setup.
confPath = "/etc/keystone/keystone.conf"

#Twilio details used for sending SMS.
twilio_from = "+16306569833"
twilio_account_sid = "ACe906adc4dc8a4cdde1cfb63e7668e496"
twilio_auth_token  = "fbc3b4fba365a13d0b362f72d113dfec"
authTimeoutDuration = 180 # in seconds

class Config:
    """
    Class responsible for all configurations related to OTP plugin.
    Includes DB and twilio setup for sending SMS.
    """
    def __init__(self):
        
        """
        For DB connection details split (username, password,host,dbname)
        """
        
        self.parser = SafeConfigParser()
        self.parser.read(confPath)
        self.configFile = self.parser.get('database', 'connection')
        self.totalValue = self.configFile.split("/");
        self.dbname = self.totalValue[3]
        self.unamePassNHost = self.totalValue[2].rsplit("@",1)
        self.host = self.unamePassNHost[1]
        self.unamePass = self.unamePassNHost[0].split(":",1)
        self.username = self.unamePass[0]
        self.password = self.unamePass[1]
        self.dbDetails = {"username": self.username,"password": self.password, "database": self.dbname, "host":self.host}
        self.getDBConnection()

    def getDBConnection(self):
        
        """
        For getting DB connection
        """
        
        import MySQLdb
        dbDetails = self.dbDetails
        
        # Open database connection - TODO - use config to get the credentials
        #db = MySQLdb.connect(dbDetails["host"],dbDetails["username"],dbDetails["password"],dbDetails["database"])
        db = MySQLdb.connect('127.0.0.1', 'root', 'demo', 'keystone')
        return db
