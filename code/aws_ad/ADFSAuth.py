# -*- coding: utf-8 -*-
"""
Author : Adam Kurowski <adam.kurowski.git@darevee.pl>

aws-ad - script to get AWS credentials using domain login and password
"""

import os
import sys
import configargparse
from argparse import RawTextHelpFormatter
import argparse
import configparser
from pprint import pprint

import requests
from bs4 import BeautifulSoup
import base64
import botocore
import boto3
import getpass
from itertools import groupby
import json

stdout = sys.stdout
stdout_redirect = None
stdout_redirect_a = None


class GetParams:
    LogLevel = 0

    username = None
    password = None
    adfs_host = None
    provider_id = None
    profile = None
    auth_file = None
    role_arn = None
    verbose = 0
    output = None
    session_duration_minutes = None

    assume_profile = None
    assume_role = None

    epilog = """
Auth File Values :

    [profile-name]
    username=login@your-domain.com
    password=your-password
    session-duration-minutes=720
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

    def logs(self, msg, warning_level='Info'):
        if self.verbose:
            print("[{}]: {}".format(warning_level, msg))

    def log_args_dict(self, info, dict_like):
        print("%s  type(dict_like)=%s  size(dict_like)=%d" % (info, str(type(dict_like)), len(dict_like)))
        for k, v in dict_like.items():
            if k == 'password':
                print("  %s = %s" % (k, '*' * len(v) if v is not None else 'None'))
            else:
                print("  %s = %s" % (k, v))

    def get_arg_parameters(self):
        parser = configargparse.ArgumentParser(description="Log into AWS using ADFS",
                                               epilog=self.epilog,
                                               formatter_class=RawTextHelpFormatter)
        parser.add_argument("--username", env_var="AWS_USERNAME", help=(
                "full domain login i.e.: user01@organisation.com"
            )
        )
        parser.add_argument("--adfs-host", env_var="AWS_ADFS_HOST", help=(
                "ADFS login domain i.e.: sts.domain.com"
            )
        )
        parser.add_argument("--provider-id", env_var="AWS_PROVIDER_ID", help=(
                "Provider ID i.e.: urn:amazon:SomeCompany"
            )
        )
        parser.add_argument("--profile", env_var="AWS_DEFAULT_PROFILE", default="default",
                            help="Profile name. if none 'default' will be picked"
        )
        parser.add_argument("--auth-file", default="~/.aws/auth", help="File with proper credentials")
        parser.add_argument("--session-duration-minutes", env_var="AWS_SESSION_DURATION_MINUTES", type=int, help="Session duration in minutes. Valid values are between 15 and 720.")
        parser.add_argument("--role-arn", env_var="AWS_ROLE_ARN", help="ARN role to assume")
        parser.add_argument("--assume-role", help="After getting login, assumes new role")
        parser.add_argument("--assume-profile", help="Profile for assumed role")
        parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity")
        parser.add_argument("--output", dest="output", choices=["file", "stdout_json"], default="file", help=(
            "suppress any intermediate output and print out the credentials only ('stdout_' is chosen)."
            "intermediate output is redirected to 'aws.log' until the end of the script is reached")
        )
        # Notice Lack of Password. It is intentional, as I don't see any reason to put password in open file
        args = parser.parse_args()

        if args.output.startswith("stdout_"):
            global stdout_redirect, stdout_redirect_a
            stdout_redirect = open("aws.log", "w")
            stdout_redirect_a = open("aws.log", "a")
            sys.stdout = stdout_redirect

        args.password = os.environ.get('AWS_PASSWORD', None)
        return args

    def get_auth_file_parameters(self):
        """

        :return:
        :rtype: argparse.Namespace
        """
        # Check if file exists
        if not os.path.isfile(os.path.expanduser(self.auth_file)):
            self.logs("No file {} found.".format(self.auth_file), 'Error')
            return {}
        self.logs("Auth file found, getting data...")
        self.logs("Profile: {}".format(self.profile))

        config = configparser.ConfigParser()
        config.read(os.path.expanduser(self.auth_file))
        if self.profile in config:
            self.logs("Profile in config found, importing...")
            r = {}
            for key, value in config[self.profile].items():
                if key in ['username', 'password', 'adfs-host', 'provider-id', 'role-arn', 'assume-role',
                           'assume-profile', 'session-duration-minutes']:
                    r[key.replace('-', '_')] = value
            return r
        else:
            self.logs("Profile [%s] not found in auth file." % (self.profile))
            return {}

    def get_parameters(self):
        cmd_line_args = vars(self.get_arg_parameters())

        self.verbose = cmd_line_args["verbose"]
        self.auth_file = cmd_line_args["auth_file"]
        self.profile = cmd_line_args["profile"]
        self.output = cmd_line_args["output"]
        self.session_duration_minutes = cmd_line_args["session_duration_minutes"]

        auth_file_args = self.get_auth_file_parameters()

        all_args = auth_file_args.copy()
        for k, v in cmd_line_args.items():
            if v is not None:
                all_args[k] = v

        if self.verbose > 2:
            self.log_args_dict("Parameters only from command line and environment variables", cmd_line_args)
            self.log_args_dict("Parameters only from config file", auth_file_args)
            self.log_args_dict("Parameters MERGED", all_args)

        for k, v in all_args.items():
            setattr(self, k, v)

        # And at least, overwrite all configuration with top priority one - got as variables
        args_missing = False
        for k in ['username', 'adfs_host', 'provider_id', 'profile', 'auth_file', 'role_arn']:
            if getattr(self, k) is None:
                args_missing = True
                print("[Error] Missing parameter for [%s]." % k)

        if (self.assume_profile and not self.assume_role) or (not self.assume_profile and self.assume_role):
            args_missing = True
            print("[Error] Either both assume-profile and assume-role must be provided or both must be absent.")

        if args_missing:
            sys.exit(1)

        if not self.password:
            print("[Warning]: No Password found")
            self.password = getpass.getpass('Password:')


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
        principial_arn, role_arn = self.pick_role()
        self.principial_arn = principial_arn
        self.role_arn = role_arn
        self.create_temporary_credentials()
        if self.parameters.assume_profile:
            self.assume_role()

    def get_saml(self):
        try:
            welcome_page_result = self.open_welcome_page()
            self.submit_credentials(welcome_page_result)
        except Exception as e:
            print("[Error]: Error getting SAML assertion: " + str(type(e)) + ": " + str(e))
            sys.exit(1)

    def open_welcome_page(self):
        """

        :rtype: WelcomePageResult
        """
        # First Query - to get client-request-id and MSISamlRequest cookie
        url = 'https://' + self.parameters.adfs_host + "/adfs/ls/IdpInitiatedSignOn.aspx"
        headers = {'cache-control': "no-cache"}
        querystring = {
            'loginToRp': self.parameters.provider_id,
            # 'client-request-id': str(uuid.uuid4()) # doesn't work, so we are using fixed value here.
            'client-request-id': '5ec0ff0e-5e4a-4a41-6be6-aaaaaffffccc'
        }
        if self.parameters.verbose > 1:
            print("Opening URL (GET): " + url)
        response = requests.request("GET", url, headers=headers, params=querystring)
        self.debug_write_file("welcome_page.html", response.text)

        if response.status_code != 200:
            raise Exception("Welcome page status_code = " + response.status_code)

        soup = BeautifulSoup(response.text, features="html.parser")

        form_element = soup.find('form', id='loginForm')
        if form_element is None:
            raise Exception("Welcome page, loginForm element not found.")

        all_input_names = [x.attrs['name'] for x in form_element.find_all('input')]
        if self.parameters.verbose > 2:
            print("Welcome page, all input elements: " + str(all_input_names))
        required_input_fields = set(['UserName', 'Password'])
        if not required_input_fields.issubset(set(all_input_names)):
            raise Exception("Welcome page, Can not find all required input fields (" + str(
                required_input_fields) + ") in fields on welcome page: " + str(set(all_input_names)))

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
        # Second Query - to get SAMLResponse
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
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

        soup = BeautifulSoup(response.text, features="html.parser")

        if response.status_code != 200:
            print(self.get_plain_text_from_soup(soup))
            raise Exception("Submit credentials response code=" + str(response.status_code))

        form_element = soup.find('form')
        if form_element is None:
            raise Exception("Submit credentials, form element not found.")

        all_input_names = [x.attrs['name'] for x in form_element.find_all('input') if 'name' in x.attrs]
        if self.parameters.verbose > 2:
            print("Submit credentials, all input elements: " + str(all_input_names))

        # Saml Response -> This contains all info neccesary to log in into system
        SAMLResponse_element = form_element.find('input', attrs={'name': 'SAMLResponse'})
        if SAMLResponse_element is None:
            print(self.get_plain_text_from_soup(soup))
            raise Exception("Submit credentials, SAMLResponse element not found.")

        SAMLResponse = SAMLResponse_element.get('value')

        if not SAMLResponse or len(SAMLResponse) < 1000:
            print(self.get_plain_text_from_soup(soup))
            raise Exception("Submit credentials, SAMLResponse element contains too short text.")

        self.parameters.logs("SAML Response - Should contain big blob of data. length = {}".format(len(SAMLResponse)))
        self.SAMLResponse = SAMLResponse

    def pick_role(self):
        SAMLResponse_decoded = base64.b64decode(self.SAMLResponse)
        soup = BeautifulSoup(SAMLResponse_decoded, features='html.parser')
        roles_html = soup.find("attribute", attrs={'name': "https://aws.amazon.com/SAML/Attributes/Role"})
        self.debug_write_file("SAMLResponse_decoded.xml", str(SAMLResponse_decoded, 'UTF-8'))

        roles = []
        print("Decoded roles:")
        for role in roles_html.find_all('attributevalue'):
            role_pair = role.text.split(',')
            principial_arn, role_arn = role_pair[0], role_pair[1]
            roles.append(role_pair)
            print("    Principal ARN: " + principial_arn + "    Role ARN: " + role_arn)
            if role_arn == self.parameters.role_arn:
                print("Role found: " + self.parameters.role_arn)
                return principial_arn, role_arn
        if len(roles) > 1:
            print(
                "Role: " + self.parameters.role_arn + " not found or multiple roles found. Please select from list below.")
            i = 0
            for role in roles:
                print("{} Role: {}".format(i, role[1]))
                i += 1
            role_nr = int(input("Choose number of role: "))
            # TODO: Proof against wrong numbers
            return roles[role_nr][0], roles[role_nr][1]
        elif len(roles) == 1:
            return roles[0][0], roles[0][1]
        else:
            print("[Error] No Role found")
            sys.exit(1)

    def create_temporary_credentials(self):
        self.make_sure_profile_exists(self.parameters.profile)

        # TODO: Implement testing if login suceeded
        # print("Hanging before the client")
        client = boto3.client('sts')
        # print("Hanging on the client")
        try:
            # print("Hanging in the try clause")
            token = client.assume_role_with_saml(
                RoleArn=self.role_arn,
                PrincipalArn=self.principial_arn,
                SAMLAssertion=self.SAMLResponse,
                DurationSeconds=int(self.parameters.session_duration_minutes) * 60 if self.parameters.session_duration_minutes else 3600
            )
        except botocore.exceptions.ClientError as err:
            print("[Error] There is a problem with assigned role:")
            print(err)
            sys.exit(1)

        # Credentials from Token:
        aws_access_key_id = token['Credentials']['AccessKeyId']
        aws_secret_key = token['Credentials']['SecretAccessKey']
        aws_session_token = token['Credentials']['SessionToken']

        # Extra info for output
        expiration = token['Credentials']['Expiration']
        assumed_dole = token['AssumedRoleUser']['Arn']
        print('Access Granted')
        print('Assumed Role : {}'.format(assumed_dole))
        print('Token Expires: {} server time'.format(expiration))

        # Now to write that config into file
        self.save_profile_credentials(self.parameters.profile,
                                      aws_access_key_id, aws_secret_key, aws_session_token, expiration,
                                      self.parameters.output)

    def assume_role(self):
        print("Creating boto3.Session with profile=%s" % self.parameters.profile)
        session = boto3.Session(profile_name=self.parameters.profile)
        sts_client = session.client('sts')
        try:
            assumedRoleObject = sts_client.assume_role(
                RoleArn=self.parameters.assume_role,
                RoleSessionName=self.parameters.assume_profile,
                DurationSeconds=int(self.parameters.session_duration_minutes) * 60 if self.parameters.session_duration_minutes else 3600
            )
        except botocore.exceptions.ClientError as err:
            print("[Error] There is a problem with assuming role:")
            print(err)
            sys.exit(1)
        print("Assumed second role: {} on profile: {}".format(self.parameters.assume_role,
                                                              self.parameters.assume_profile))
        credentials = assumedRoleObject['Credentials']

        self.save_profile_credentials(self.parameters.assume_profile, credentials['AccessKeyId'],
                                      credentials['SecretAccessKey'], credentials['SessionToken'],
                                      "",self.parameters.output)

    def save_profile_credentials(self, profile_name, access_key, secret_access_key, session_token, expiration, output):

        if output == "file":
            home = os.path.expanduser("~")
            filename = home + '/.aws/credentials'
            print("Reading file " + filename)
            aws_credentials = configparser.ConfigParser()
            aws_credentials.read(filename)
            aws_credentials[profile_name] = {
                'aws_access_key_id': access_key,
                'aws_secret_access_key': secret_access_key,
                'aws_session_token': session_token
            }
            config_folder = home + '/.aws'
            os.makedirs(config_folder, exist_ok=True)

            print("Writing file " + filename + " with updated profile [" + profile_name + "]")
            with open(filename, 'w') as configfile:
                aws_credentials.write(configfile)
        elif output.startswith("stdout_"):
            sys.stdout = stdout
            credentials = {
                "Version": 1,
                "AccessKeyId": access_key,
                "SecretAccessKey": secret_access_key,
                "SessionToken": session_token,
                "Expiration": expiration.isoformat(sep=" ")
            }
            print(json.dumps(credentials))
            sys.stdout = stdout_redirect_a

    def make_sure_profile_exists(self, profile_name):
        home = os.path.expanduser("~")
        filename = home + '/.aws/config'
        print("Reading file " + filename)
        aws_profiles_data = configparser.ConfigParser()
        aws_profiles_data.read(filename)

        profile_label = "profile " + profile_name
        if profile_name == "default":
            profile_label = "default"

        if profile_label not in aws_profiles_data:
            print("Profile %s not found. Creating one..." % profile_name)
            aws_profiles_data[profile_label] = {}

            config_folder = home + '/.aws'
            os.makedirs(config_folder, exist_ok=True)

            print("Writing file " + filename + " with updated profile [" + profile_name + "]")
            with open(filename, 'w') as configfile:
                aws_profiles_data.write(configfile)
        else:
            print("Profile %s exists." % profile_name)

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
        text = "\n".join(lines)
        return text

    def debug_write_file(self, filename, content_str):
        if type(content_str) is not str:
            content_str = str(content_str)
        if self.parameters.verbose > 2:
            print("Writing to file: " + filename)
            with open(filename, "w") as f:
                f.write(content_str)


def main_func():
    ADFSAuth()
