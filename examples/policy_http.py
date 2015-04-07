from Zorp.Core import *
from Zorp.Http import *

InetZone(name="internet", addrs=["0.0.0.0/0"])

def zorp_http():
        Service("http", HttpProxyNonTransparent, router=InbandRouter())
        Listener(SockAddrInet("0.0.0.0", 8080), "http")
