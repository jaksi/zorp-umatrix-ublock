import random
from datetime import datetime, timedelta

from Zorp.Core import *
from Zorp.Http import *


InetZone(name="internet", addrs=["0.0.0.0/0"])


class uMatrix_uBlock_Proxy(HttpProxyNonTransparent):
    user_agents = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18',
    ]
    user_agent_interval = timedelta(minutes=5)
    current_user_agents = {} # a dict mapping IP addresses to tuples containing the current user agent associated with them, and the last time they were changed

    def config(self):
        HttpProxyNonTransparent.config(self)
        self.request["GET"] = (HTTP_REQ_POLICY, self.handleRequest)
        self.request["POST"] = (HTTP_REQ_POLICY, self.handleRequest)

    def handleRequest(self, method, url, version):
        if method == 'POST' and self.getRequestHeader('Content-Type') == 'text/ping':
            return HTTP_REQ_REJECT

        now = datetime.now()
        src = self.session.client_address.ip_s

        user_agent, last_changed = uMatrix_uBlock_Proxy.current_user_agents.get(src, (None, None))
        if not user_agent or now - last_changed > uMatrix_uBlock_Proxy.user_agent_interval:
            user_agent = random.choice(uMatrix_uBlock_Proxy.user_agents)
            uMatrix_uBlock_Proxy.current_user_agents[src] = (user_agent, now)
        self.setRequestHeader('User-Agent', user_agent)

        return HTTP_REQ_ACCEPT


def zorp_uMatrix_uBlock():
        Service("uMatrix_uBlock", uMatrix_uBlock_Proxy, router=InbandRouter())
        Listener(SockAddrInet("0.0.0.0", 8080), "uMatrix_uBlock")
