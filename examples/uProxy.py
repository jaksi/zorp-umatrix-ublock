import random
from datetime import datetime, timedelta
from urlparse import urlparse

from Zorp.Http import *


class uProxy(HttpProxyNonTransparent):
    user_agents = []
    user_agent_interval = timedelta(minutes=5)
    block_hyperlink_auditing = False
    strict_https_experimental = False
    spoof_referer = False

    _current_user_agents = {} # a dict mapping IP addresses to tuples containing the current user agent associated with them, and the last time they were changed

    def config(self):
        HttpProxyNonTransparent.config(self)
        self.request["GET"] = (HTTP_REQ_POLICY, self.handleRequest)
        self.request["POST"] = (HTTP_REQ_POLICY, self.handleRequest)

    def handleRequest(self, method, url, version):
        if uProxy.block_hyperlink_auditing:
            if method == 'POST' and self.getRequestHeader('Content-Type') == 'text/ping':
                # TODO: log
                return HTTP_REQ_REJECT

        if uProxy.strict_https_experimental:
            # TODO: and this is an HTTP request
            # TODO: if the headers are present
            if 'text/html' not in self.getRequestHeader('Accept') and self.getRequestHeader('Referer').startswith('https'):
                # TODO: log
                return HTTP_REQ_REJECT

        if uProxy.spoof_referer:
            # TODO: if the headers are present
            if self.getRequestHeader('Host') != urlparse(self.getRequestHeader('Referer')).netloc:
                # TODO: remove request header entirely
                self.setRequestHeader('Referer', '')

        now = datetime.now()
        src = self.session.client_address.ip_s

        if uProxy.user_agents:
            user_agent, last_changed = uProxy.current_user_agents.get(src, (None, None))
            if not user_agent or now - last_changed > uProxy.user_agent_interval:
                user_agent = random.choice(uProxy.user_agents)
                uProxy.current_user_agents[src] = (user_agent, now)
                # TODO: log
            self.setRequestHeader('User-Agent', user_agent)

        return HTTP_REQ_ACCEPT
