from datetime import timedelta

from Zorp.Core import *
from uProxy import uProxy


InetZone(name="internet", addrs=["0.0.0.0/0"])

# Spoof User-Agent string by randomly picking a new one below every 2 minutes
uProxy.user_agents = [
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18',
]
uProxy.user_agent_interval = timedelta(minutes=2)

# Block all hyperlink auditing attempts
uProxy.block_hyperlink_auditing = True

# Spoof HTTP referrer string of third-party requests
uProxy.spoof_referer = True

def zorp_uProxy():
        Service("uProxy", uProxy, router=InbandRouter())
        Listener(SockAddrInet("0.0.0.0", 8080), "uProxy")
