import json
import random
from datetime import datetime, timedelta
from urlparse import urlparse

from Zorp.Http import *


class uProxy(HttpProxyNonTransparent):
    delete_session_cookies = False
    unused_session_cookie_lifetime = timedelta(minutes=60)

    spoof_referer = False

    block_hyperlink_auditing = False

    user_agents = []
    user_agent_interval = timedelta(minutes=5)

    enable_matrix = False
    matrix_file = '/etc/zorp/matrix.json'

    _current_session_cookies = {} # a dict mapping tuples of IP addresses and cookies to the last time they were used
    _current_user_agents = {} # a dict mapping IP addresses to tuples containing the current user agent associated with them, and the last time they were changed

    def config(self):
        HttpProxyNonTransparent.config(self)

        self.response_header["Set-Cookie"] = (HTTP_HDR_POLICY, self.processSetCookie)
        self.request_header["Cookie"] = (HTTP_HDR_POLICY, self.processCookie)

        if uProxy.spoof_referer:
            self.request_header["Referer"] = (HTTP_HDR_POLICY, self.processReferer)

        self.request["POST"] = (HTTP_REQ_POLICY, self.handlePostRequest)

        if uProxy.user_agents:
            self.request_header["User-Agent"] = (HTTP_HDR_POLICY, self.processUserAgent)

        self.response["*"] = (HTTP_RSP_POLICY, self.handleResponse)
        if uProxy.enable_matrix:
            with open(uProxy.matrix_file) as f:
                uProxy._matrix = json.load(f)
            for i, rule in enumerate(uProxy._matrix['rules']):
                if 'type' in rule:
                    uProxy._matrix['rules'][i]['type'] = self.typeShortcut(rule['type'])


    def typeShortcut(self, types):
        r = []
        for t in types:
            if t == 'JavaScript':
                r.extend(['application/x-javascript', 'application/javascript', 'text/javascript'])
            elif t == 'CSS':
                r.append('text/css')
            elif t == 'Media':
                r.extend('image', 'audio', 'video')
            else:
                r.append(t)
        return r


    def processSetCookie(self, name, value):
        now = datetime.now()

        if uProxy.enable_matrix:
            if not self.cookieAllowed():
                return HTTP_HDR_DROP

        if not uProxy.delete_session_cookies:
            return HTTP_HDR_ACCEPT

        # if the cookie contains an 'expires' field, therefore not being a session cookie
        if [c for c in value.split('; ')[1:] if c.startswith('expires')]:
            return HTTP_HDR_ACCEPT

        src = self.session.client_address.ip_s
        uProxy._current_session_cookies[(src, value)] = now
        return HTTP_HDR_ACCEPT


    def processCookie(self, name, value):
        now = datetime.now()
        src = self.session.client_address.ip_s

        if uProxy.enable_matrix:
            if not self.cookieAllowed():
                return HTTP_HDR_DROP

        if not uProxy.delete_session_cookies:
            return HTTP_HDR_ACCEPT

        if (src, value) not in uProxy._current_session_cookies:
            return HTTP_HDR_ACCEPT

        last_use = uProxy._current_session_cookies[(src, value)]
        if now - last_use > uProxy.unused_session_cookie_lifetime:
            return HTTP_HDR_DROP

        uProxy._current_session_cookies[(src, value)] = now
        return HTTP_HDR_ACCEPT


    def cookieAllowed(self):
        host = self.getRequestHeader('Host')

        netloc = host.split('.')
        for precedence in range(len(netloc)):
            rule_host = '.'.join(netloc[precedence:])
            for rule in uProxy._matrix['rules']:
                if ('hostname' in rule and rule_host in rule['hostname'] and 
                        'type' in rule and 'Cookie' in rule['type']):
                    proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, 'Cookie', 'accepted' if rule['allow'] else 'rejected'))
                    return rule['allow']

        for precedence in range(len(netloc)):
            rule_host = '.'.join(netloc[precedence:])
            for rule in uProxy._matrix['rules']:
                if 'hostname' in rule and rule_host in rule['hostname'] and 'type' not in rule:
                    proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, 'Cookie', 'accepted' if rule['allow'] else 'rejected'))
                    return rule['allow']

        for rule in uProxy._matrix['rules']:
            if ('hostname' not in rule and
                    'type' in rule and 'Cookie' in rule['type']):
                proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, 'Cookie', 'accepted' if rule['allow'] else 'rejected'))
                return rule['allow']
            
        return uProxy._matrix['allow']
        

    def processReferer(self, name, value):
        host = self.getRequestHeader('Host')
        referer = self.getRequestHeader('Referer')

        if referer and host != urlparse(referer).netloc:
            proxyLog(self, 'Privacy', 3, '3rd party referer "%s" to "%s" spoofed' % (referer, host))
            return HTTP_HDR_DROP
        return HTTP_HDR_ACCEPT


    def handlePostRequest(self, method, url, version):
        if uProxy.block_hyperlink_auditing:
            if self.getRequestHeader('Content-Type') == 'text/ping':
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


    def handleResponse(self, method, url, version, status):
        if not uProxy.enable_matrix:
            return HTTP_RSP_ACCEPT

        host = self.getRequestHeader('Host')
        content_type = self.getResponseHeader('Content-Type')
        mime = content_type.split(';')[0] if content_type else ''

        netloc = host.split('.')
        for precedence in range(len(netloc)):
            rule_host = '.'.join(netloc[precedence:])
            for rule in uProxy._matrix['rules']:
                if ('hostname' in rule and rule_host in rule['hostname'] and 
                        'type' in rule and (mime in rule['type'] or mime.split('/')[0] in rule['type'])):
                    proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, mime, 'accepted' if rule['allow'] else 'rejected'))
                    return HTTP_RSP_ACCEPT if rule['allow'] else HTTP_RSP_REJECT

        for precedence in range(len(netloc)):
            rule_host = '.'.join(netloc[precedence:])
            for rule in uProxy._matrix['rules']:
                if 'hostname' in rule and rule_host in rule['hostname'] and 'type' not in rule:
                    proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, mime, 'accepted' if rule['allow'] else 'rejected'))
                    return HTTP_RSP_ACCEPT if rule['allow'] else HTTP_RSP_REJECT

        for rule in uProxy._matrix['rules']:
            if ('hostname' not in rule and
                    'type' in rule and (mime in rule['type'] or mime.split('/')[0] in rule['type'])):
                proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, mime, 'accepted' if rule['allow'] else 'rejected'))
                return HTTP_RSP_ACCEPT if rule['allow'] else HTTP_RSP_REJECT
            
        return HTTP_RSP_ACCEPT if uProxy._matrix['allow'] else HTTP_RSP_REJECT
