#!/usr/bin/env python
# encoding: utf-8
##############################################################################
##############################################################################
##############################################################################
###
### oauth/__init__.py
###
### This is for OAUTH authentication.
###
##############################################################################
##############################################################################
##############################################################################

import re
import urllib
import urlparse
import hmac
import binascii
import random
import time

AUTH_HEADER_OAUTH = 'Authorization'

OAUTH_VERSION = '1.0'

def escape(s):
    """Escape a URL including any /."""
    return urllib.quote(s, '-._~')

def generate_timestamp():
    """Get seconds since epoch (UTC)."""
    return int(time.time())

def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def generate_verifier(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def normalise_url(url):
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)

    # Exclude default port numbers.
    if scheme == 'http' and netloc[-3:] == ':80':
        netloc = netloc[:-3]
    elif scheme == 'https' and netloc[-4:] == ':443':
        netloc = netloc[:-4]
    if scheme not in ('http', 'https'):
        raise ValueError("Unsupported URL %s (%s)." % (value, scheme))

    # Normalized URL excludes params, query, and fragment.
    return urlparse.urlunparse((scheme, netloc, path, None, None, None))

def split_url_string(param_str):
    """Turn URL string into parameters."""
    parameters = urlparse.parse_qs(param_str, keep_blank_values=False)
    for k, v in parameters.iteritems():
        parameters[k] = urllib.unquote(v[0])
    return parameters

def get_normalized_parameters(params, url):
    """Return a string that contains the parameters that must be signed."""
    items = []
    for key, value in params.iteritems():
        if key == 'oauth_signature':
            continue
        # 1.0a/9.1.1 states that kvp must be sorted by key, then by value,
        # so we unpack sequence values into multiple items for sorting.
        if hasattr(value, '__iter__'):
            items.extend((key, item) for item in value)
        else:
            items.append((key, value))

    # Include any query string parameters from the provided URL
    query = urlparse.urlparse(url)[4]
    
    url_items = split_url_string(query).items()
    non_oauth_url_items = list([(k, v) for k, v in url_items  if not k.startswith('oauth_')])
    items.extend(non_oauth_url_items)

    encoded_str = urllib.urlencode(sorted(items))
    # Encode signature parameters per Oauth Core 1.0 protocol
    # spec draft 7, section 3.6
    # (http://tools.ietf.org/html/draft-hammer-oauth-07#section-3.6)
    # Spaces must be encoded with "%20" instead of "+"
    return encoded_str.replace('+', '%20').replace('%7E', '~')

class SignatureMethod(object):
    """A way of signing requests.

    The OAuth protocol lets consumers and service providers pick a way to sign
    requests. This interface shows the methods expected by the other `oauth`
    modules for signing requests. Subclass it and implement its methods to
    provide a new way to sign requests.
    """

    def signing_base(self, params, url, method, consumer, token):
        """Calculates the string that needs to be signed.

        This method returns a 2-tuple containing the starting key for the
        signing and the message to be signed. The latter may be used in error
        messages to help clients debug their software.

        """
        raise NotImplementedError

    def sign(self, params, url, method, consumer, token):
        """Returns the signature for the given request, based on the consumer
        and token also provided.

        You should use your implementation of `, ()` to build the
        message to sign. Otherwise it may be less useful for debugging.

        """
        raise NotImplementedError

    def check(self, params, url, method, consumer, token, signature):
        """Returns whether the given signature is the correct signature for
        the given consumer and token signing the given request."""
        built = self.sign(params, url, method, consumer, token)
        return built == signature

class SignatureMethod_HMAC_SHA1(SignatureMethod):
    name = 'HMAC-SHA1'

    def signing_base(self, params, url, method, consumer, token):
        norm_url = normalise_url(url)

        if norm_url is None:
            raise ValueError("Base URL for request is not set.")

        sig = (
            escape(method),
            escape(norm_url),
            escape(get_normalized_parameters(params, url)),
        )

        key = '%s&' % escape(consumer.secret)
        if token:
            key += escape(token.secret)
        raw = '&'.join(sig)
        return key, raw

    def sign(self, params, url, method, consumer, token):
        """Builds the base signature string."""
        key, raw = self.signing_base(params, url, method, consumer, token)

        # HMAC object.
        try:
            from hashlib import sha1 as sha
        except ImportError:
            import sha # Deprecated

        hashed = hmac.new(key, raw, sha)

        # Calculate the digest base 64.
        return binascii.b2a_base64(hashed.digest())[:-1]


class SignatureMethod_PLAINTEXT(SignatureMethod):

    name = 'PLAINTEXT'

    def signing_base(self, params, url, method, consumer, token):
        """Concatenates the consumer key and secret with the token's
        secret."""
        sig = '%s&' % escape(consumer.secret)
        if token:
            sig = sig + escape(token.secret)
        return sig, sig

    def sign(self, params, url, method, consumer, token):
        key, raw = self.signing_base(params, url, method, consumer, token)
        return raw

class KeySecret(object):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

def generate_header(params, realm):
    """Serialize as a header for an HTTPAuth request."""
    oauth_params = ((k, v) for k, v in params.items() 
                        if k.startswith('oauth_'))
    stringy_params = ((k, escape(str(v))) for k, v in oauth_params)
    header_params = ('%s="%s"' % (k, v) for k, v in stringy_params)
    params_header = ', '.join(header_params)

    auth_header = 'OAuth realm="%s"' % realm
    if params_header:
        auth_header = "%s, %s" % (auth_header, params_header)

    return auth_header

def get_oauth_header(req, consumer, token, realm=''):
    params = {}
    # The version of oauth
    params['oauth_version'] = OAUTH_VERSION
    # Suitable nonce value
    params['oauth_nonce'] = generate_nonce()
    # Timestamp to stop replay attacks
    params['oauth_timestamp'] = generate_timestamp()

    if consumer:
        params['oauth_consumer_key'] = consumer.key
    else:
        raise Exception('No consumer key given.')

    if token:
        params['oauth_token'] = token.key

    signature_method = SignatureMethod_HMAC_SHA1()
    params['oauth_signature_method'] = signature_method.name
    # Your signature using token and consumer secrets
    params['oauth_signature'] = signature_method.sign(params, req.get_full_url(), req.get_method(), consumer, token)
    return generate_header(params, realm)
