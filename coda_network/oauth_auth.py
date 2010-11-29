#!/usr/bin/env python
# encoding: utf-8
##############################################################################
##############################################################################
##############################################################################
###
### oauth_auth.py
###
### This is for OAUTH authentication.
###
##############################################################################
##############################################################################
##############################################################################

import re

from coda_network import urllib2
from coda_network.oauth import get_oauth_header, AUTH_HEADER_OAUTH

class AbstractOauthAuthHandler:

    # allow for double- and single-quoted realm values
    # (single quotes are a violation of the RFC, but appear in the wild)
    #rx = re.compile('(?:.*,)*[ \t]*([^ \t]+)[ \t]+'
    #                'realm=(["\'])(.*?)\\2', re.I)
    rx = re.compile('([^\"\'=]*)=[\"\']([^\"\'=]*)[\"\'][ \t,]*', re.IGNORECASE)
    def __init__(self, password_mgr=None):
        if password_mgr is None:
            password_mgr = urllib2.HTTPPasswordMgr()
        self.passwd = password_mgr
        self.add_password = self.passwd.add_password
        self.retried = 0

    def http_error_auth_reqed(self, authreq, host, req, headers):
        # host may be an authority (without userinfo) or a URL with an
        # authority
        # XXX could be multiple headers
        authreq = headers.get(authreq, None)

        if self.retried > 2:
            # retry sending the username:password 5 times before failing.
            raise urllib2.HTTPError(req.get_full_url(), 401, "oauth auth failed",
                            headers, None)
        else:
            self.retried += 1

        if authreq:
            auth_items = authreq.split(' ')
            scheme = auth_items[0].strip().lower()
            auth_dict = {}
            for auth in auth_items[1:]:
                mo = AbstractOauthAuthHandler.rx.search(auth)
                if mo:
                    name, val = mo.groups()
                    auth_dict[name] = val
            if scheme.lower() == 'oauth':
                return self.retry_http_oauth_auth(host, req, auth_dict.get('realm', ''))

    def retry_http_oauth_auth(self, host, req, realm):
        auth = self.generate_oauth_header(host, req)
        if auth:
            req.add_unredirected_header(self.auth_header, auth)
            return self.parent.open(req, timeout=req.timeout)
        else:
            return None

    def generate_oauth_header(self, host, req):
        consumer, token = self.passwd.find_user_password(None, host)
        if consumer is not None:
            auth = get_oauth_header(req, consumer, token)
            if req.headers.get(self.auth_header, None) != auth:
                return auth
        return None

class HTTPOauthAuthHandler(AbstractOauthAuthHandler, urllib2.BaseHandler):

    auth_header = AUTH_HEADER_OAUTH

    def http_error_401(self, req, fp, code, msg, headers):
        url = req.get_full_url()
        return self.http_error_auth_reqed('www-authenticate',
                                          url, req, headers)
