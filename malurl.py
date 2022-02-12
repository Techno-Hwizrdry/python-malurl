# Copyright: 2022, Alexan Mardigian
__version__ = "1.0.0"

import json
import requests
from csv import DictWriter
from validators import ValidationFailure, url as validate_url
from urllib.parse import quote_plus

DOES_NOT_EXIST = -999

class MalURL:
    def __init__(self, apikey, strictness=0):
        self.apikey = apikey
        self.strictness = strictness
        self.results = {}

    def fetch(self, url):
        """
        Sets self.results to a dictionary representing the JSON response
        from IP Quality Score.  The url parameter will be validated
        before a request to IP Quality Score is made.  This is done
        to conserve our monthly request limit, in case url is invalid.  
        
        Parameters
        ----------
        url: string
        """
        if not self._is_valid_url(url):
            self.results = {
                "success": False,
                "message": f"Invalid url {url}"
            }
            return

        BASE = 'https://www.ipqualityscore.com/api/json/url'
        encoded_url = quote_plus(url)
        api_url = f'{BASE}/{self.apikey}/{encoded_url}?{self.strictness}'

        response = requests.get(api_url)
        self.results = json.loads(response.content.decode('utf-8'))

    def print(self):
        """
        Output a limited amount of fields to standard output.

        Parameters
        ----------
        None.
        """
        domain = self.domain()
        print(domain)
        print('-' * len(domain))

        if not self.success():
            print(f'message: {self.message()}')
            print(f'status:  {self.status_code()}')
            return

        print(f'IP Address: {self.ip_address()}')
        print(f'Category:   {self.category()}')
        print(f'Adult:      {self.adult()}')
        print(f'Malware:    {self.malware()}')
        print(f'Phishing:   {self.phishing()}')
        print(f'Spamming:   {self.spamming()}')
        print(f'Suspicious: {self.suspicious()}')
        print(f'Unsafe:     {self.unsafe()}')
        print(f'Risk score: {self.risk_score()}')

    def unsafe(self):
        """
        Returns boolean value indicating if the domain is suspected of
        being unsafe due to phishing, malware, spamming, or abusive
        behavior. View the confidence level by analyzing the "risk_score". 
        
        Parameters
        ----------
        None.
        """
        return bool(self._get('unsafe'))

    def domain(self):
        """
        Returns a string representing the domain name of the final
        destination URL of the scanned link, after following all redirects.
        Returns an empty string if 'domain' is not available. 
        
        Parameters
        ----------
        None.
        """
        return self._get('domain')

    def ip_address(self):
        """
        Returns a string representing the IP address
        corresponding to the server of the domain name.
        Returns an empty string if 'ip_address' is not available.
        
        Parameters
        ----------
        None.
        """
        return self._get('ip_address')

    def server(self):
        """
        Returns a string representing server banner of the domain's IP address.
        For example: "nginx/1.16.0".  "N/A" is returned if unavailable.
        
        Parameters
        ----------
        None.
        """
        s = self._get('server')
        return s if s else 'N/A'

    def content_type(self):
        """
        Returns a string representing the MIME type of URL's content.
        For example "text/html; charset=UTF-8". 
        "N/A" is returned if unavailable.
        
        Parameters
        ----------
        None.
        """
        ct = self._get('content_type')
        return ct if ct else 'N/A'

    def risk_score(self):
        """
        Returns an integer representing the The IPQS risk score which estimates
        the confidence level for malicious URL detection. Risk Scores 85+ are
        high risk, while Risk Scores = 100 are confirmed as accurate.  If no
        risk score exists, then DOES_NOT_EXIST will be returned.
        
        Parameters
        ----------
        None.
        """
        risk_score = self._get('risk_score')
        return risk_score if risk_score != '' else DOES_NOT_EXIST

    def status_code(self):
        """
        Returns an integer representing the HTTP Status Code of the URL's
        response. This value should be 200 for a valid website.
        0 is returned if URL is unreachable.

        Parameters
        ----------
        None.
        """
        status = self._get('status_code')
        return status if status else 0

    def page_size(self):
        """
        Returns an integer representing the Total number of bytes to download
        the URL's content. 0 is returned if URL is unreachable.

        Parameters
        ----------
        None.
        """
        ps = self._get('page_size')
        return ps if ps else 0

    def domain_rank(self):
        """
        Returns an integer representing the estimated popularity rank of
        website globally. Returns 0 if the domain is unranked or has low
        traffic.  Returns DOES_NOT_EXIST if unreachable.

        Parameters
        ----------
        None.
        """
        rank = self._get('domain_rank')
        return rank if rank != '' else DOES_NOT_EXIST

    def dns_valid(self):
        """
        Returns boolean value indicating if the domain of the URL has valid
        DNS records.

        Parameters
        ----------
        None.
        """
        return bool(self._get('dns_valid'))

    def suspicious(self):
        """
        Returns boolean value indicating if the URL is suspected of being
        malicious or used for phishing or abuse. Use in conjunction with
        the risk_score() method as a confidence level.

        Parameters
        ----------
        None.
        """
        return bool(self._get('suspicious'))

    def phishing(self):
        """
        Returns boolean value indicating if the URL is
        associated with malicious phishing behavior.

        Parameters
        ----------
        None.
        """
        return bool(self._get('phishing'))

    def malware(self):
        """
        Returns boolean value indicating if the URL is
        associated with malware or viruses.

        Parameters
        ----------
        None.
        """
        return bool(self._get('malware'))

    def parking(self):
        """
        Returns boolean value indicating if the URL is
        currently parked with a for sale notice.

        Parameters
        ----------
        None.
        """
        return bool(self._get('parking'))

    def spamming(self):
        """
        Returns boolean value indicating if the URL is
        associated with email SPAM or abusive email addresses.

        Parameters
        ----------
        None.
        """
        return bool(self._get('spamming'))

    def adult(self):
        """
        Returns boolean value indicating if the URL or
        domain is hosting dating or adult content.

        Parameters
        ----------
        None.
        """
        return bool(self._get('adult'))

    def category(self):
        """
        Returns a string representing the website classification and category
        related to the content and industry of the site. Over 70 categories
        are available including "Video Streaming", "Trackers", "Gaming",
        "Privacy", "Advertising", "Hacking", "Malicious", "Phishing", etc.
        The value returned will be "N/A" if unknown.
        
        Parameters
        ----------
        None.
        """
        cat = self._get('category')
        return cat if cat else 'N/A'

    def domain_age(self):
        """
        Returns a dictionary representing the domain age of the URL.
        If 'domain_age' is not available, then an empty dictionary
        will be returned.
        
        Parameters
        ----------
        None.
        """
        age = self._get('domain_age')
        return age if age else {}

    def message(self):
        """
        Returns a generic status message, either success or
        some form of an error notice.
        
        Parameters
        ----------
        None.
        """
        return self._get('message')

    def success(self):
        """
        Returns a boolean indicating if the request to IPQS was successful.
        
        Parameters
        ----------
        None.
        """
        return self._get('success')

    def request_id(self):
        """
        Returns a string representing the unique identifier for this request
        that can be used to lookup the request details or send a postback
        conversion notice.
        
        Parameters
        ----------
        None.
        """
        return self._get('request_id')

    def errors(self):
        """
        Returns a list of strings representing the errors which
        occurred while attempting to process this request.
        
        Parameters
        ----------
        None.
        """
        errs = self._get('errors')
        return errs if errs else []


    def _get(self, key):
        return self.results[key] if key in self.results else ''

    def _is_valid_url(self, url):
        is_valid = validate_url(url)

        if isinstance(is_valid, ValidationFailure):
            return False

        return is_valid