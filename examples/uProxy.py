import json
import random
import re
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

    enable_abp = False
    abp_filter = '/etc/zorp/abp.txt'

    _current_session_cookies = {} # a dict mapping tuples of IP addresses and cookies to the last time they were used
    _current_user_agents = {} # a dict mapping IP addresses to tuples containing the current user agent associated with them, and the last time they were changed

    @staticmethod
    def load():
        if uProxy.enable_matrix:
            with open(uProxy.matrix_file) as f:
                uProxy._matrix = json.load(f)
            for i, rule in enumerate(uProxy._matrix['rules']):
                if 'type' in rule:
                    uProxy._matrix['rules'][i]['type'] = uProxy.typeShortcut(rule['type'])

        if uProxy.enable_abp:
            uProxy._abp_rules = []
            element_hiding = 0
            with open(uProxy.abp_filter) as f:
                for line in f:
                    line = line[:-1]
                    if line[0] == '!':
                        continue
                    split = line.split('$')
                    rule = split[0]
                    if '##' in rule:
                        element_hiding += 1
                        continue
                    options = '$'.join(split[1:])
                    types = []
                    not_types = []
                    domains = []
                    not_domains = []
                    match_case = False
                    allowed = False
                    if rule.startswith('@@|http'):
                        allowed = True
                        rule = rule[7:]
                    elif rule.startswith('@@'):
                        allowed = True
                        rule = rule[2:]
                    if options:
                        for option in options.split(','):
                            if option == 'script':
                                types.append('script')
                            elif option == 'image':
                                types.append('image')
                            elif option == 'stylesheet':
                                types.append('stylesheet')
                            elif option == 'document':
                                types.append('document')
                            elif option == '~script':
                                not_types.append('script')
                            elif option == '~image':
                                not_types.append('image')
                            elif option == '~stylesheet':
                                not_types.append('stylesheet')
                            elif option == '~document':
                                not_types.append('document')

                            elif option == 'match-case':
                                match_case = True

                            elif option.startswith('domain='):
                                for domain in option[7:].split('|'):
                                    if domain[0] == '~':
                                        not_domains.append(domain)
                                    else:
                                        domains.append(domain)
                            else:
                                continue
                    if rule[0] == '/' and rule[-1] == '/':
                        rule = rule[1:-1]
                    else:
                        rule = re.escape(rule)
                        rule = rule.replace(r'\*', '.*')
                        rule = rule.replace(r'\^', r'[^\w\-.%]')
                        if rule[-2:] == r'\|':
                            rule = rule[:-2] + '$'
                        if rule[:4] == r'\|\|':
                            rule = '^' + rule[:4]
                    uProxy._abp_rules.append(
                        {
                            'allowed': allowed,
                            'rule': rule,
                            'types': types,
                            'not_types': not_types,
                            'domains': domains,
                            'not_domains': not_domains,
                            'match_case': match_case
                        }
                    )
        

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


    @staticmethod
    def typeShortcut(types):
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
            if not self.typeAllowed('Cookie'):
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
        host = self.getRequestHeader('Host')

        if uProxy.enable_matrix:
            if not self.typeAllowed('Cookie'):
                return HTTP_HDR_DROP

        if not uProxy.delete_session_cookies:
            return HTTP_HDR_ACCEPT

        if (src, value) not in uProxy._current_session_cookies:
            return HTTP_HDR_ACCEPT

        last_use = uProxy._current_session_cookies[(src, value)]
        if now - last_use > uProxy.unused_session_cookie_lifetime:
            proxyLog(self, 'Privacy', 3, 'Expired session cookie from %s rejected.' % host)
            return HTTP_HDR_DROP

        uProxy._current_session_cookies[(src, value)] = now
        return HTTP_HDR_ACCEPT


    def typeAllowed(self, mime):
        host = self.getRequestHeader('Host')

        netloc = host.split('.')
        for precedence in range(len(netloc)):
            rule_host = '.'.join(netloc[precedence:])
            for rule in uProxy._matrix['rules']:
                if ('hostname' in rule and rule_host in rule['hostname'] and 
                        'type' in rule and (mime in rule['type'] or mime.split('/')[0] in rule['type'])):
                    proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, mime, 'accepted' if rule['allow'] else 'rejected'))
                    return rule['allow']

        for precedence in range(len(netloc)):
            rule_host = '.'.join(netloc[precedence:])
            for rule in uProxy._matrix['rules']:
                if 'hostname' in rule and rule_host in rule['hostname'] and 'type' not in rule:
                    proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, mime, 'accepted' if rule['allow'] else 'rejected'))
                    return rule['allow']

        for rule in uProxy._matrix['rules']:
            if ('hostname' not in rule and
                    'type' in rule and (mime in rule['type'] or mime.split('/')[0] in rule['type'])):
                proxyLog(self, 'Matrix', 3, 'Response from "%s" with type "%s" %s' % (host, mime, 'accepted' if rule['allow'] else 'rejected'))
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
        content_type = self.getResponseHeader('Content-Type')
        mime = content_type.split(';')[0] if content_type else ''
        host = self.getRequestHeader('Host')
        if uProxy.enable_matrix:
            content_type = self.getResponseHeader('Content-Type')
            mime = content_type.split(';')[0] if content_type else ''

            if not self.typeAllowed(mime):
                return HTTP_RSP_REJECT

        if uProxy.enable_abp:
            for rule in filter(lambda r: r['allowed'], uProxy._abp_rules):
                if (re.search(rule['rule'], url, flags=re.IGNORECASE if not rule['match_case'] else '') and
                        (not rule['types'] or mime in rule['types']) and (not rule['not_types'] or mime not in rule['not_types']) and
                        (not rule['domains'] or host in rule['domains']) and (not rule['not_domains'] or rule not in rule['not_domains'])):
                    proxyLog(self, 'ABP', 3, 'Response from %s whitelisted' % host)
                    return HTTP_RSP_ACCEPT

            for rule in filter(lambda r: not r['allowed'], uProxy._abp_rules):
                if (re.search(rule['rule'], url, flags=re.IGNORECASE if not rule['match_case'] else '') and
                        (not rule['types'] or mime in rule['types']) and (not rule['not_types'] or mime not in rule['not_types']) and
                        (not rule['domains'] or host in rule['domains']) and (not rule['not_domains'] or rule not in rule['not_domains'])):
                    proxyLog(self, 'ABP', 3, 'Response from %s blacklisted' % host)
                    return HTTP_RSP_REJECT

        return HTTP_RSP_ACCEPT
