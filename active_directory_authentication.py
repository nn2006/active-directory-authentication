import os
from dotenv import load_dotenv

from ldap3 import Server, Connection,  NTLM
from jwt import encode, decode, ExpiredSignatureError
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
dotenv_path1 = rf'C:\Users\Adil\Desktop\handson\LDAP\update\.env'
load_dotenv(dotenv_path1)
print(dotenv_path1)
#home = str(Path.home())
class ADAuthenticator:
    def __init__(self):
        self.access_token_expiry = timedelta(minutes=30)
        self.access_token_secret = 'MySecretKey'
        # Load environment variables from .env file
        
    def ldap_authenticate(self, username, password):
        """
            Access to AD using LDAP with given Credentials ladap
        """
        #domain = os.environ.get('DOMAIN')
        #username = domain + username
        ldap_server = "ldap://"+os.environ.get('USERDNSDOMAIN')
        print(ldap_server)
        server = Server(ldap_server, port=389, use_ssl=False, get_info='ALL')
        conn = Connection(server, user=username, password=password,
                          authentication=NTLM)

        if conn.bind():
            return True
        else:
            return False
    def ldap_authenticateAdil( self,username, password):
        """
            Access to AD using LDAP with given Credentials ladap
        """
        domain = os.environ.get('DOMAIN')
        username1 = domain + username
        ldap_server = os.environ.get('LDAP_SERVER')
        server = Server(ldap_server, port=389, use_ssl=False, get_info='ALL')
        conn = Connection(server, user=username1, password=password,
                          authentication=NTLM)

        if conn.bind():
            return True
        else:
            return False
    def generate_access_token(self, username):
        """
            Generate the Access Token for username
        """
        expiry_time = datetime.utcnow() + self.access_token_expiry
        payload = {'username': username, 'exp': expiry_time}
        access_token = encode(payload, self.access_token_secret, algorithm='HS256')
        return access_token

    def renew_access_token(self, access_token):
        """
             Renew the Access Token for same username
        """
        try:
            payload = decode(access_token, self.access_token_secret, algorithms=['HS256'])
            username = payload['username']
            renewed_token = self.generate_access_token(username)
            return renewed_token
        except:
            return None

    def validate_access_token(self, access_token):
        """
             Validate the Access Token the same username
        """

        try:
            payload = decode(access_token, self.access_token_secret, algorithms=['HS256'])
            expiry_time = datetime.fromtimestamp(payload['exp'])
            if expiry_time < datetime.utcnow():
                # Token has expired
                return False
            return True
        except ExpiredSignatureError:
            # Token has expired
            return False
        except:
            # Token is invalid
            return False

    def get_auth(self, username, password):
        """
            Run the Authenticator with given username and password
        """
        domain = os.environ.get('USERDNSDOMAIN')+"\\"
        print(domain)
        username = domain + username
        password = password

        if self.ldap_authenticate(username, password):
            access_token = self.generate_access_token(username)
            logging.info(
                f"LDAP authentication successful - Access Token: {access_token}")
            

            ###### For test the renew and valdition #####

            renewed_token = self.renew_access_token(access_token)
            if renewed_token:
                 print(f'Renewed Access Token: {renewed_token}')
            else:
                 print('Token renewal failed')

            # Simulate usage after some time
            # Uncomment the following lines to test token validation after some time
            import time
            time.sleep(120)  # Sleep for 2 minutes
            valid = self.validate_access_token(access_token)
            print(f'Token Valid: {valid}')
            return access_token
            ###### For test the renew and valdition #####

        else:
            logging.warning(f"LDAP authentication failed for {username}")


if __name__ == '__main__':
   
    username1 = os.environ.get('USERNAME')
    password = os.environ.get('password')

    print (username1) 
    print (password) 
    
    authenticator = ADAuthenticator()
    access_token = authenticator.get_auth(username1, password)
    print(access_token)
    #if authenticator.ldap_authenticateAdil(username, password):
    #        print("tst")
    #print("adil")
