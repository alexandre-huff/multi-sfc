# -*- coding: utf-8 -*-
# Copyright (C) Cardiff University (2020)
#
# This file is part of requests_ecp.
#
# requests_ecp is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# requests_ecp is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with requests_ecp.  If not, see <http://www.gnu.org/licenses/>.

"""Auth plugin for ECP requests
"""

__author__ = "Duncan Macleod <duncan.macleod@ligo.org>"
__version__ = "0.2.1"

from distutils.version import LooseVersion
from getpass import getpass
from urllib import parse as urllib_parse
from urllib.error import URLError

from requests import (
    auth as requests_auth,
    Request,
    Session as _Session,
)
from requests.cookies import extract_cookies_to_jar

from requests_kerberos import (
    __version__ as REQUESTS_KERBEROS_VERSION,
    HTTPKerberosAuth,
)

from lxml import etree

__all__ = [
    "HTTPECPAuth",
    "ECPAuthSessionMixin",
    "Session",
]

REQUESTS_KERBEROS_VERSION = LooseVersion(REQUESTS_KERBEROS_VERSION)


def _get_xml_attribute(xdata, path):
    """Parse an attribute from an XML document
    """
    namespaces = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
    }
    return xdata.xpath(path, namespaces=namespaces)[0]


def _prompt_username_password(host, username=None):
    """Prompt for a username and password from the console
    """
    if not username:
        username = input("Enter username for {0}: ".format(host))
    password = getpass(
        "Enter password for {0!r} on {1}: ".format(username, host),
    )
    return username, password


class HTTPECPAuth(requests_auth.AuthBase):
    def __init__(
            self,
            idp,
            kerberos=False,
            username=None,
            password=None,
    ):
        #: Address of Identity Provider ECP endpoint.
        self.idp = idp

        #: Authentication object to attach to requests made directly
        #: to the IdP.
        self.kerberos = kerberos
        self.username = username
        self.password = password
        self._idpauth = None

        #: counter for authentication attemps for a single request
        self._num_ecp_auth = 0

    @staticmethod
    def _init_auth(idp, kerberos=False, username=None, password=None):
        if kerberos:
            url = kerberos if isinstance(kerberos, str) else idp
            loginhost = urllib_parse.urlparse(url).netloc.split(':')[0]
            return HTTPKerberosAuth(
                force_preemptive=True,
                hostname_override=loginhost,
            )
        elif username and password:
            return requests_auth.HTTPBasicAuth(username, password)
        return requests_auth.HTTPBasicAuth(*_prompt_username_password(
            urllib_parse.urlparse(idp).hostname,
            username,
        ))

    # -- utilities ----------

    def _report_soap_fault(self, connection, url, **kwargs):
        """Report a problem with the SOAP configuration of SP/IdP pair
        """
        request = Request(
            method="POST",
            url=url,
            headers={'Content-Type': 'application/vnd.paos+xml'},
            data="""
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Body>
    <S:Fault>
      <faultcode>S:Server</faultcode>
      <faultstring>responseConsumerURL from SP and assertionConsumerServiceURL from IdP do not match</faultstring>
    </S:Fault>
  </S:Body>
</S:Envelope>""", # noqa
        ).prepare()
        return connection.send(request, **kwargs)

    # -- auth method --------

    def authenticate(self, session, endpoint=None, url=None, **kwargs):
        url = url or endpoint or self.idp
        adapter = session.get_adapter(url=url)
        # authenticate and store cookies
        for resp in self._authenticate(adapter, url=url):
            extract_cookies_to_jar(session.cookies, resp.request, resp.raw)

    def _authenticate_response(self, response, endpoint=None, **kwargs):
        response.raw.release_conn()
        return self._authenticate(
            response.connection,
            endpoint=endpoint,
            url=response.url,
            **kwargs
        )

    def _authenticate(
            self,
            connection,
            endpoint=None,
            url=None,
            cookies=None,
            **kwargs
    ):
        """Handle user authentication with ECP
        """
        endpoint = endpoint or self.idp
        target = url or endpoint

        if self._idpauth is None:
            self._idpauth = self._init_auth(
                self.idp,
                kerberos=self.kerberos,
                username=self.username,
                password=self.password,
            )

        # -- step 1: initiate ECP request -----------

        req1 = Request(
            method="GET",
            url=target,
            cookies=cookies,
            headers={
                'Accept': 'text/html; application/vnd.paos+xml',
                'PAOS': 'ver="urn:liberty:paos:2003-08";'
                        '"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"',
            },
        ).prepare()

        # request target from SP
        resp1 = connection.send(req1, **kwargs)

        # convert the SP resonse from string to etree Element object
        try:
            spetree = etree.XML(resp1.content)
        finally:
            resp1.raw.release_conn()

        # pick out the relay state element from the SP so that it can
        # be included later in the response to the SP
        relaystate = _get_xml_attribute(
            spetree,
            "//ecp:RelayState",
        )
        rcurl = _get_xml_attribute(
            spetree,
            "/S:Envelope/S:Header/paos:Request/@responseConsumerURL",
        )

        # remote the SOAP header to create a packge for the IdP
        idpbody = spetree
        idpbody.remove(idpbody[0])

        # -- step 2: authenticate with endpoint -----

        req2 = Request(
            method="POST",
            url=endpoint,
            auth=self._idpauth,
            cookies=cookies,
            data=etree.tostring(idpbody),
            headers={"Content-Type": "text/xml; charset=utf-8"},
        ).prepare()
        resp2 = connection.send(req2, **kwargs)

        # -- step 3: post back to the SP ------------

        try:
            idptree = etree.XML(resp2.content)
        except etree.XMLSyntaxError:
            raise RuntimeError(
                "Failed to parse response from {}, you most "
                "likely incorrectly entered your passphrase".format(
                    endpoint,
                ),
            )
        finally:
            resp2.raw.release_conn()
        acsurl = _get_xml_attribute(
            idptree,
            "/S:Envelope/S:Header/ecp:Response/@AssertionConsumerServiceURL",
        )

        # validate URLs between SP and IdP
        if acsurl != rcurl:
            try:
                self._report_soap_fault(connection, rcurl)
            except URLError:
                pass  # don't care, just doing a service

        # make a deep copy of the IdP response and replace its
        # header contents with the relay state initially sent by
        # the SP
        actree = idptree
        actree[0][0] = relaystate

        # POST the package to the SP
        req3 = Request(
            method="POST",
            url=acsurl,
            cookies=cookies,
            data=etree.tostring(actree),
            headers={'Content-Type': 'application/vnd.paos+xml'},
        ).prepare()
        resp3 = connection.send(req3)

        # return all responses
        return resp1, resp2, resp3

    # -- auth discovery -----

    @staticmethod
    def is_ecp_auth_redirect(response):
        """Return `True` if a response indicates a request for authentication
        """
        if not response.is_redirect:
            return False

        # strip out the redirect location and parse it
        target = response.headers['location']
        if isinstance(target, bytes):
            target = target.decode("utf-8")
        query = urllib_parse.parse_qs(urllib_parse.urlparse(target).query)

        return (
                "SAMLRequest" in query or  # redirected to IdP
                "Shibboleth.sso" in target  # Shibboleth discovery service
        )

    # -- event handling -----

    def handle_response(self, response, **kwargs):
        """Handle ECP authentication based on a transation response
        """
        # if the request was redirected in a way that looks like the SP
        # is asking for ECP authentication, then handle that here:
        # (but only do that once)
        if self.is_ecp_auth_redirect(response) and not self._num_ecp_auth:
            # authenticate (preserving the history)
            """ Huff
                We need to read the response to release it for the new request
                This response is no longer needed since it is a redirect asking
                for authentication. The client will send a new request using ECP.
            """
            response.text
            response.history.extend(
                self._authenticate_response(response, **kwargs),
            )

            # and hijack the redirect back to itself
            response.headers['location'] = response.url
            self._num_ecp_auth += 1
        else:
            self._num_ecp_auth = 0

        return response

    def deregister(self, response):
        """Deregister the response handler
        """
        response.request.deregister_hook('response', self.handle_response)

    def __call__(self, request):
        """Register the response handler
        """
        request.register_hook('response', self.handle_response)
        return request


class ECPAuthSessionMixin:
    """A mixin for `requests.Session` to add default ECP Auth
    """
    def __init__(
            self,
            idp=None,
            kerberos=False,
            username=None,
            password=None,
            **kwargs
    ):
        super().__init__(**kwargs)
        self.auth = HTTPECPAuth(
            idp,
            kerberos=kerberos,
            username=username,
            password=password,
        )


class Session(ECPAuthSessionMixin, _Session):
    """A `requests.Session` with default ECP authentication
    """
    def ecp_authenticate(self, endpoint=None, url=None, **kwargs):
        """Manually authenticate against the endpoint

        This generates a shibboleth session cookie for the domain
        of the given URL, which defaults to the endpoint itself.
        """
        return self.auth.authenticate(
            self,
            endpoint=endpoint,
            url=url,
            **kwargs
        )
