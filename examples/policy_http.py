from Zorp.Core import *
from Zorp.Http import *
import random


InetZone(name="internet", addrs=["0.0.0.0/0"])


class MatrixProxy(HttpProxyNonTransparent):
	user_agents = [
		'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0',
		'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18',
	]

	def config(self):
		HttpProxyNonTransparent.config(self)
		self.request_header["User-Agent"] = (HTTP_HDR_CHANGE_VALUE, random.choice(MatrixProxy.user_agents))
		self.request["POST"] = (HTTP_REQ_POLICY, self.blockAudits)

	def blockAudits(self, method, url, version):
		if self.getRequestHeader('Content-Type') == 'text/ping':
                        return HTTP_REQ_REJECT
		return HTTP_REQ_ACCEPT


def zorp_http():
        Service("http", MatrixProxy, router=InbandRouter())
        Listener(SockAddrInet("0.0.0.0", 8080), "http")
