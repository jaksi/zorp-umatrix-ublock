import random
from datetime import datetime, timedelta
from urlparse import urlparse

from Zorp.Http import *


class uProxy(HttpProxyNonTransparent):
    spoof_referer = False

    block_hyperlink_auditing = False

    user_agents = []
    user_agent_interval = timedelta(minutes=5)

    _current_user_agents = {} # a dict mapping IP addresses to tuples containing the current user agent associated with them, and the last time they were changed

    def config(self):
        HttpProxyNonTransparent.config(self)

        if uProxy.spoof_referer:
            self.request_header["Referer"] = (HTTP_HDR_POLICY, self.processReferer)

        self.request["POST"] = (HTTP_REQ_POLICY, self.handlePostRequest)

        if uProxy.user_agents:
            self.request_header["User-Agent"] = (HTTP_HDR_POLICY, self.processUserAgent)


    def processReferer(self, name, value):
        host = self.getRequestHeader('Host')
        referer = self.getRequestHeader('Referer')

        if referer and host != urlparse(referer).netloc:
            proxyLog(self, 'Privacy', 3, '3rd party referer "%s" to "%s" spoofed' % (referer, host))
            self.current_header_value = ''
        return HTTP_HDR_ACCEPT


    def handlePostRequest(self, method, url, version):
        if uProxy.block_hyperlink_auditing:
            if method == 'POST' and self.getRequestHeader('Content-Type') == 'text/ping':
                proxyLog(self, 'Privacy', 3, 'Hyperlink auditing attempt to "%s" rejected' % url)
                return HTTP_REQ_REJECT
        return HTTP_REQ_ACCEPT


    def processUserAgent(self, name, value):
        now = datetime.now()
        src = self.session.client_address.ip_s

        user_agent, last_changed = uProxy._current_user_agents.get(src, (None, None))
        if not user_agent or now - last_changed > uProxy.user_agent_interval:
            user_agent = random.choice(uProxy.user_agents)
            uProxy._current_user_agents[src] = (user_agent, now)
            proxyLog(self, 'Privacy', 3, 'User-Agent of client %s replaced with "%s" for %s' % (src, user_agent, uProxy.user_agent_interval))
            self.current_header_value = user_agent
        return HTTP_HDR_ACCEPT
