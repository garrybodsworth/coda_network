#!/usr/bin/env python
# encoding: utf-8
##############################################################################
##############################################################################
##############################################################################
###
### ntlm_auth.py
###
### This is for NTLM authentication.
###
##############################################################################
##############################################################################
##############################################################################

import re

from coda_network import urllib2
from coda_network.ntlm import ntlm

NTLM_HEADER = re.compile(r'NTLM(?: (.*))?', re.I)

class AbstractNtlmAuthHandler:
    def __init__(self, password_mgr=None, debuglevel=0):
        if password_mgr is None:
            password_mgr = urllib2.HTTPPasswordMgr()
        self.passwd = password_mgr
        self.add_password = self.passwd.add_password
        self._debuglevel = debuglevel

    def set_http_debuglevel(self, level):
        self._debuglevel = level

    def get_user_password(self, realm, req):
        return self.passwd.find_user_password(realm, req.get_full_url())

    def http_error_authentication_required(self, auth_header_field, req, fp, headers):
        auth_header_value = headers.get(auth_header_field, None)
        if auth_header_field:
            header_match = NTLM_HEADER.search(auth_header_value)
        if header_match:
            fp.close()
            challenge_message = header_match.group(1)
            if not challenge_message:
                # The first stage of authorization
                return self.authenticate_using_http_NTLM(req, auth_header_field, None, headers)
            else:
                # The second stage of authorization
                return self.authorize_using_http_NTLM(req, auth_header_field, None, headers)

    def authenticate_using_http_NTLM(self, req, auth_header_field, realm, headers):
        user, pw = self.get_user_password(realm, req)
        if pw is not None:
            auth = 'NTLM %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE(user)
            if req.headers.get(self.auth_header, None) == auth:
                return None
            req.add_header(self.auth_header, auth)
            # We need to use the parent to open and keep the connection because NTLM authenticates the connection, not single requests
            req.add_header('Connection', 'Keep-Alive')
            return self.parent.open(req)
        else:
            return None

    def authorize_using_http_NTLM(self, req, auth_header_field, realm, headers):
        user, pw = self.get_user_password(realm, req)
        if pw is not None:
            cookie = headers.get('set-cookie', None)
            if cookie:
                # this is important for some web applications that store authentication-related info in cookies (it took a long time to figure out)
                req.add_header('Cookie', cookie)
            auth_header_value = headers.get(auth_header_field, None)
            (ServerChallenge, NegotiateFlags) = ntlm.parse_NTLM_CHALLENGE_MESSAGE(auth_header_value[5:])
            user_parts = user.split('\\', 1)
            DomainName = user_parts[0].upper()
            UserName = user_parts[1]
            auth = 'NTLM %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(ServerChallenge, UserName, DomainName, pw, NegotiateFlags)
            req.add_header(self.auth_header, auth)
            return self.parent.open(req)
        else:
            return None

class HTTPNtlmAuthHandler(AbstractNtlmAuthHandler, urllib2.BaseHandler):

    auth_header = 'Authorization'

    def http_error_401(self, req, fp, code, msg, headers):
        return self.http_error_authentication_required('www-authenticate', req, fp, headers)


class ProxyNtlmAuthHandler(AbstractNtlmAuthHandler, urllib2.BaseHandler):

    auth_header = 'Proxy-authorization'

    def http_error_407(self, req, fp, code, msg, headers):
        req.proxy_connection_type = headers.get('Proxy-Connection', 'close')
        return self.http_error_authentication_required('proxy-authenticate', req, fp, headers)

    def get_user_password(self, realm, req):
        return self.passwd.find_user_password(realm, req.get_host())
