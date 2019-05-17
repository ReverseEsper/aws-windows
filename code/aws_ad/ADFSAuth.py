#-*- coding: utf-8 -*-
"""
Author : Adam Kurowski <adam.kurowski.git@darevee.pl>

aws-ad - script to get AWS credentials using domain login and password
"""

import os
import sys
import argparse
from argparse import RawTextHelpFormatter
import configparser

import requests
from bs4 import BeautifulSoup
import base64
import botocore
import boto3
import getpass
from itertools import groupby


class GetParams:
    LogLevel = 0

    username = ''
    password = ''
    adfs_host = ''
    provider_id = ''
    profile = 'default'
    auth_file = '~/.aws/auth'
    role_arn = ''
    verbose = 0

    assume_profile = ''
    assume_role = ''

    epilog = """
Environmental Variables : 

    AWS_USERNAME
    AWS_PASSWORD
    AWS_DEFAULT_PROFILE
    AWS_ADFS_HOST
    AWS_PROVIDER_ID
    AWS_ROLE_ARN

Auth File Values :

    [profile-name]
    username=login@your-domain.com
    password=your-password
    adfs-host=sts.your-domain.com
    provider-id=urn:amazon:your-company-provider-id
    role-arn=arn:aws:iam::1234567890:role/ADFS_ROLE_FOR_TASK
    # Extra variables that changes behaviour of profile :    
    assume-role=arn:aws:iam::1234567890:role/role-to-assume-into-after-gettin-in
    assume-profile=name-of-the-new-profile

Two last option are optional and only in case when you need to assume another role straight after logging in
if from both options, only assume-role is present, assume-profile will owervrite main profile credentials

Command line parameters take precedence over auth file and environmental variables
auth file parameters take precedence over environmental variables
    
    """

    def __init__(self):
        self.get_parameters()
        self.logs("Log parameters  - username: {}".format(self.username))
        # self.logs("Log parameters  - Password: {}".format(self.password))
        self.logs("Log parameters  - adfs_host: {}".format(self.adfs_host))
        self.logs("Log parameters  - provider_id: {}".format(self.provider_id))
        self.logs("Log parameters  - profile: {}".format(self.profile))
        self.logs("Log parameters  - auth_file: {}".format(self.auth_file))
        self.logs("Log parameters  - role_arn: {}".format(self.role_arn))
        self.logs("Log parameters  - verbose: {}".format(self.verbose))

    def logs(self,msg,warning_level='Info'):
        if self.verbose:
            print ("[{}]: {}".format(warning_level,msg))

    def get_env_parameters(self):
        envs  = {
            'AWS_USERNAME':'username','AWS_PASSWORD':'password',
            'AWS_DEFAULT_PROFILE':'profile','AWS_ADFS_HOST':'adfs-host',
            'AWS_PROVIDER_ID':'provider-id','AWS_ROLE_ARN':'role-arn'
        }
        for key in envs:
            if key in os.environ:
                self.logs ("Key Env: {}  importing ".format(key))
                value = os.environ[key]   
                if key == 'AWS_USERNAME': 
                    self.username = value
                elif key == 'AWS_PASSWORD':
                    self.password = value
                elif key == 'AWS_ADFS_HOST':
                    self.adfs_host = value
                elif key == 'AWS_PROVIDER_ID':
                    self.provider_id = value
                elif key == 'AWS_ROLE_ARN':
                    self.role_arn = value
                elif key == 'AWS_DEFAULT_PROFILE':
                    self.profile = value

    def get_arg_parameters(self):
        #Prepare Command Variables
        parser = argparse.ArgumentParser(description="Log into AWS using ADFS",epilog=self.epilog,formatter_class=RawTextHelpFormatter)
        parser.add_argument("--username", help="full domain login i.e.: user01@organisation.com")
        parser.add_argument("--adfs-host", help="ADFS login domain i.e.: sts.domain.com")
        parser.add_argument("--provider-id", help="Provider ID i.e.: urn:amazon:SomeCompany")
        parser.add_argument("--profile", help="Profile name. if none 'default' will be picked", default="default")
        parser.add_argument("--auth-file", help="File with proper credentials")
        parser.add_argument("--role-arn", help="ARN role to assume")
        parser.add_argument("--assume-role", help="After getting login, assumes new role")
        parser.add_argument("--assume-profile", help="Profile for assumed role")
        parser.add_argument("-v","--verbose", help="Increase output verbosity",action="count", default=0)
        # Notice Lack of Password. It is intentional, as I don't see any reason to put password in open file
        args = parser.parse_args()
        return args

    def get_auth_file_parameters(self):
        # Check if file exists
        if not os.path.isfile(os.path.expanduser(self.auth_file)):
            self.logs("No file {} found.".format(self.auth_file),'Error')
            return
        self.logs("Auth file found, getting data...")
        profile = self.profile
        self.logs("Profile: {}".format(profile))

        config = configparser.ConfigParser()
        config.read(os.path.expanduser(self.auth_file))
        if profile in config:
            self.logs ("Profile in config found, importing...")
            for key,value in config[profile].items():
                self.logs("Key: {} importing".format(key))
                if key == 'username': 
                    self.username = value
                elif key == 'password':
                    self.password = value
                elif key == 'adfs-host':
                    self.adfs_host = value
                elif key == 'provider-id':
                    self.provider_id = value
                elif key == 'role-arn':
                    self.role_arn = value
                elif key == 'assume-role':
                    self.assume_role = value
                elif key == 'assume-profile':
                    self.assume_profile = value
        if self.assume_profile and not self.assume_role:
            print ("[Error] assume-profile provided, yet no Assume_Role found")
            sys.exit(1)

    def get_parameters(self):
        self.get_env_parameters()
        args = self.get_arg_parameters()
        
        self.verbose = args.verbose
        if args.auth_file:
            self.auth_file = args.auth_file
        if args.profile:
            self.profile = args.profile

        self.get_auth_file_parameters()
        
        # And at least, overwrite all configuration with top priority one - got as variables
        for key,value in vars(args).items():
            if value:
                if key == 'username': 
                    self.username = value
                elif key == 'adfs_host':
                    self.adfs_host = value
                elif key == 'provider_id':
                    self.provider_id = value
                elif key == 'role_arn':
                    self.role_arn = value
                elif key == 'assume_role':
                    self.assume_role = value
                elif key == 'assume_profile':
                    self.assume_profile = value
            if self.assume_profile and not self.assume_role:
                print ("[Error] Assume_Profile provided, yet no Assume_Role found")
                sys.exit(1)
        #If assume_role is assigned ,but assume_profile is not, use main profile
        if self.assume_role and not self.assume_profile:
            self.assume_profile = self.profile

        #Assert that critical variables are present
        if not self.username :
            print ("[Error]: No Username found")
            sys.exit(1)
        if not self.password:
            print ("[Warning]: No Password found")
            self.password = getpass.getpass('Password:')
        if not self.adfs_host:
            print ("[Error]: No ADFS Host found")
            sys.exit(1)
        if not self.provider_id :
            print ("[Error]: No Provider ID found")
            sys.exit(1)
        return


class WelcomePageResult:
    cookies = None
    action = None

    def __str__(self):
        return "LoginPageResult(action=" + self.action + ")"


class ADFSAuth:
    SAMLResponse = ''
    parameters = ''
    principial_arn = ''
    role_arn = ''

    def __init__(self):
        self.parameters = GetParams()
        self.get_saml()
        principial_arn,role_arn = self.pick_role()
        self.principial_arn = principial_arn
        self.role_arn= role_arn
        self.create_temporary_credentials()
        if self.parameters.assume_profile:
            self.assume_role()
        
    def get_saml(self):
        try:
            welcome_page_result = self.open_welcome_page()
            self.submit_credentials(welcome_page_result)
        except Exception as e:
            print ("[Error]: Error getting SAML assertion: " + str(e))
            sys.exit(1)

    def open_welcome_page(self):
        """

        :rtype: WelcomePageResult
        """
        #First Query - to get client-request-id and MSISamlRequest cookie
        url = 'https://'+self.parameters.adfs_host+"/adfs/ls/IdpInitiatedSignOn.aspx"
        headers = {'cache-control': "no-cache"}
        querystring = {
            'loginToRp': self.parameters.provider_id,
            # 'client-request-id': str(uuid.uuid4()) # doesn't work, so we are using fixed value here.
            'client-request-id': '5ec0500e-584a-4a41-6b26-aaaaaffffccc'
        }
        if self.parameters.verbose > 1:
            print("Opening URL (GET): " + url)
        response = requests.request("GET", url, headers=headers, params=querystring)
        self.debug_write_file("welcome_page.html", response.text)

        if response.status_code != 200:
            raise Exception("Welcome page status_code = " + response.status_code)

        soup = BeautifulSoup(response.text, features="lxml")

        form_element = soup.find('form', id='loginForm')
        if form_element is None:
            raise Exception("Welcome page, loginForm element not found.")

        all_input_names = [x.attrs['name'] for x in form_element.find_all('input')]
        if self.parameters.verbose > 2:
            print("Welcome page, all input elements: " + str(all_input_names))
        required_input_fields = set(['UserName', 'Password'])
        if not required_input_fields.issubset(set(all_input_names)):
            raise Exception("Welcome page, Can not find all required input fields (" + str(required_input_fields) + ") in fields on welcome page: " + str(set(all_input_names)))

        r = WelcomePageResult()
        r.cookies = response.cookies
        r.action = form_element.get('action')
        return r

    def submit_credentials(self, welcome_page_result):
        """

        :param welcome_page_result:
        :type welcome_page_result: WelcomePageResult
        :return:
        """
        #Second Query - to get SAMLResponse
        headers = { 'Content-Type':'application/x-www-form-urlencoded'}
        form = {
            'UserName': self.parameters.username,
            'Password': self.parameters.password,
            'AuthMethod': 'FormsAuthentication'
        }
        url2 = 'https://' + self.parameters.adfs_host + welcome_page_result.action
        if self.parameters.verbose > 1:
            print("Opening URL (POST): " + url2)
        response = requests.request("POST", url2, headers=headers, data=form, cookies=welcome_page_result.cookies)
        self.debug_write_file("submit_credentials.html", response.text)

        soup = BeautifulSoup(response.text,features="lxml")

        if response.status_code != 200:
            print(self.get_plain_text_from_soup(soup))
            raise Exception("Submit credentials response code=" + str(response.status_code))

        form_element = soup.find('form')
        if form_element is None:
            raise Exception("Submit credentials, form element not found.")

        #Saml Response -> This contains all info neccesary to log in into system
        SAMLResponse_element = form_element.find('input', attrs={'name': 'SAMLResponse'})
        if SAMLResponse_element is None:
            raise Exception("Submit credentials, SAMLResponse element not found.")

        SAMLResponse = SAMLResponse_element.get('value')

        if not SAMLResponse or len(SAMLResponse) < 1000:
            print(self.get_plain_text_from_soup(soup))
            raise Exception("Submit credentials, SAMLResponse element contains too short text.")

        self.parameters.logs("SAML Response - Should contain big blob of data. length = {}".format(len(SAMLResponse)))
        self.SAMLResponse = SAMLResponse

    def pick_role(self):
        SAMLResponse_decoded = base64.b64decode(self.SAMLResponse)
        soup = BeautifulSoup(SAMLResponse_decoded, features='lxml')
        roles_html = soup.find("attribute",attrs={'name':"https://aws.amazon.com/SAML/Attributes/Role"})
        self.debug_write_file("SAMLResponse_decoded.xml", str(SAMLResponse_decoded, 'UTF-8'))

        roles = []
        print("Decoded roles:")
        for role in roles_html.find_all('attributevalue'):
            role_pair = role.text.split(',')
            principial_arn,role_arn = role_pair[0], role_pair[1]
            roles.append(role_pair)
            print("    Principal ARN: " + principial_arn + "    Role ARN: " + role_arn)
            if role_arn == self.parameters.role_arn:
                print ("Role found: " + self.parameters.role_arn)
                return principial_arn, role_arn
        if len(roles) > 1 :
            print("Role: " + self.parameters.role_arn  + " not found or multiple roles found. Please select from list below.")
            i=0
            for role in roles:
                print ("{} Role: {}".format(i,role[1]))
                i += 1
            role_nr = int(input("Choose number of role: "))
            # TODO: Proof against wrong numbers
            return roles[role_nr][0], roles[role_nr][1]
        elif len(roles) == 1:
            return roles[0][0], roles[0][1]
        else:
            print ("[Error] No Role found") 
            sys.exit(1)

    def create_temporary_credentials(self):
        # TODO: Implement testing if login suceeded
        client = boto3.client('sts')
        try:
            token = client.assume_role_with_saml(
                RoleArn=self.role_arn,
                PrincipalArn=self.principial_arn,
                SAMLAssertion=self.SAMLResponse,
                DurationSeconds=3600
            )
        except botocore.exceptions.ClientError as err:
            print ("[Error] There is a problem with assigned role:")
            print (err)
            sys.exit(1)

        #Credentials from Token:
        aws_access_key_id = token['Credentials']['AccessKeyId']
        aws_secret_key = token['Credentials']['SecretAccessKey']
        aws_session_token = token['Credentials']['SessionToken']
        profile = self.parameters.profile

        # Extra info for output
        expiration = token['Credentials']['Expiration']
        assumed_dole = token['AssumedRoleUser']['Arn']
        print ('Access Granted')
        print ('Assumed Role : {}'.format(assumed_dole))
        print ('Token Expires: {} server time'.format(expiration))

        # Now to write that config into file
        self.save_profile_credentials(profile, aws_access_key_id, aws_secret_key, aws_session_token)
    
    def assume_role(self):
        session = boto3.Session(profile_name=self.parameters.profile)
        sts_client = session.client('sts')
        try:         
            assumedRoleObject = sts_client.assume_role(
                RoleArn=self.parameters.assume_role,
                RoleSessionName=self.parameters.assume_profile
            )
        except botocore.exceptions.ClientError as err:
            print ("[Error] There is a problem with assuming role:")
            print (err)
            sys.exit(1)
        print ("Assumed second role: {} on profile: {}".format(self.parameters.assume_role,self.parameters.assume_profile))
        credentials = assumedRoleObject['Credentials']

        self.save_profile_credentials(self.parameters.assume_profile, credentials['AccessKeyId'], credentials['SecretAccessKey'], credentials['SessionToken'])

    def save_profile_credentials(self, profile_name, access_key, secret_access_key, session_token):
        home = os.path.expanduser("~")
        filename = home + '/.aws/credentials'
        print("Reading file " + filename)
        aws_credentials = configparser.ConfigParser()
        aws_credentials.read(filename)
        aws_credentials[profile_name]= {
            'aws_access_key_id': access_key,
            'aws_secret_access_key': secret_access_key,
            'aws_session_token': session_token
        }
        config_folder = home+'/.aws'
        if not os.path.exists(config_folder):
            os.makedirs(config_folder)

        print("Writing file " + filename + " with updated profile [" + profile_name + "]")
        with open(filename, 'w') as configfile:
            aws_credentials.write(configfile)

    def get_plain_text_from_soup(self, soup):
        # remove tags that has JS or CSS
        for script in soup(["script", "style"]):
            script.decompose()

        # get only text from HTML
        text = soup.get_text()

        # break into lines and remove leading and trailing space on each
        lines = (line.strip() for line in text.splitlines())

        # remove duplicate lines (especially blank lines)
        lines = [x[0] for x in groupby(lines)]

        # join all lines into single string
        text = '\n'.join(lines)
        return text.encode("ascii", errors="replace")

    def debug_write_file(self, filename, content_str):
        if type(content_str) is not str:
            content_str = str(content_str)
        if self.parameters.verbose > 2:
            print("Writing to file: " + filename)
            with open(filename, "w") as f:
                f.write(content_str)


def main_func():
    authentication = ADFSAuth()
