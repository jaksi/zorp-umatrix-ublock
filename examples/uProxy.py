import random
from datetime import datetime, timedelta
from urlparse import urlparse

from Zorp.Http import *


class uProxy(HttpProxyNonTransparent):
    user_agents = []
    user_agent_interval = timedelta(minutes=5)
    block_hyperlink_auditing = False
    spoof_referer = False

    _current_user_agents = {} # a dict mapping IP addresses to tuples containing the current user agent associated with them, and the last time they were changed

    def config(self):
        HttpProxyNonTransparent.config(self)
        self.request["GET"] = (HTTP_REQ_POLICY, self.handleRequest)
        self.request["POST"] = (HTTP_REQ_POLICY, self.handleRequest)

    def handleRequest(self, method, url, version):
        now = datetime.now()
        src = self.session.client_address.ip_s
        host = self.getRequestHeader('Host')
        referer = self.getRequestHeader('Referer')

        if uProxy.block_hyperlink_auditing:
            if method == 'POST' and self.getRequestHeader('Content-Type') == 'text/ping':
                proxyLog(self, '', 0, 'Hyperlink auditing attempt to %s rejected' % host)
                return HTTP_REQ_REJECT

        if uProxy.spoof_referer:
            if referer and host != urlparse(referer).netloc:
                proxyLog(self, '', 0, '3rd party referer (%s) to %s spoofed' % (referer, host))
                self.setRequestHeader('Referer', '')

        if uProxy.user_agents:
            user_agent, last_changed = uProxy._current_user_agents.get(src, (None, None))
            if not user_agent or now - last_changed > uProxy.user_agent_interval:
                user_agent = random.choice(uProxy.user_agents)
                uProxy._current_user_agents[src] = (user_agent, now)
                proxyLog(self, '', 0, 'User-Agent of client %s replaced with %s for %s' % (src, user_agent, uProxy.user_agent_interval))
            self.setRequestHeader('User-Agent', user_agent)

        return HTTP_REQ_ACCEPT
