# Copyright: 2022, Alexan Mardigian

import json
import requests
from typing import Dict, List
from validators import ValidationFailure, url as validate_url
from urllib.parse import quote_plus
from rainbowprint import rprint

DOES_NOT_EXIST = -999
NA = 'N/A'

class MalURL:
    def __init__(self, apikey: str, strictness: int=0) -> None:
        self.apikey = apikey
        self.strictness = strictness
        self.results = {}

    def fetch(self, url: str) -> None:
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
            self.results = self._no_results(404, f"Invalid url {url}")
            return

        BASE = 'https://www.ipqualityscore.com/api/json/url'
        encoded_url = quote_plus(url)
        api_url = f'{BASE}/{self.apikey}/{encoded_url}?{self.strictness}'

        try:
            response = requests.get(api_url)
            self.results = json.loads(response.content.decode('utf-8'))
            
            # If we have exceeded our API request quota, then modify
            # the results with a 402 (payment required) status_code.
            req = 'You have exceeded your request quota'
            msg = self.message()
            if not self.success() and req in msg:
                self.results = self._no_results(402, msg)
        except requests.exceptions.ConnectionError:
            msg = "Failed to establish connection to IP Quality Score API."
            self.results = self._no_results(503, msg)

    def _print(self, text: str, rainbow: bool) -> None:
        if rainbow:
            rprint(text, 1)
        else:
            print(text)

    def print(self, rainbow: bool=False) -> None:
        """
        Output a limited amount of fields to standard output.

        Parameters
        ----------
        rainbow: boolean (optional)
        """
        domain = self.domain()
        header = f'{domain}\n{"-" * len(domain)}' 

        if not self.success():
            print(header)
            print(f'message: {self.message()}')
            print(f'status:  {self.status_code()}')
            return

        # To color the output in a gradient, and avoid
        # just having output with different colored lines,
        # the output string must be built before it is
        # printed.  As opposed to rprint line by line.
        output = header
        output += f'\nIP Address: {self.ip_address()}\n'
        output += f'Category:   {self.category()}\n'
        output += f'Adult:      {self.adult()}\n'
        output += f'Malware:    {self.malware()}\n'
        output += f'Phishing:   {self.phishing()}\n'
        output += f'Spamming:   {self.spamming()}\n'
        output += f'Suspicious: {self.suspicious()}\n'
        output += f'Unsafe:     {self.unsafe()}\n'
        output += f'Risk score: {self.risk_score()}'

        self._print(output, rainbow)

    def unsafe(self) -> bool:
        """
        Returns boolean value indicating if the domain is suspected of
        being unsafe due to phishing, malware, spamming, or abusive
        behavior. View the confidence level by analyzing the "risk_score". 
        
        Parameters
        ----------
        None.
        """
        return bool(self.results.get('unsafe'))

    def domain(self) -> str:
        """
        Returns a string representing the domain name of the final
        destination URL of the scanned link, after following all redirects.
        Returns an empty string if 'domain' is not available. 
        
        Parameters
        ----------
        None.
        """
        return self.results.get('domain', '')

    def ip_address(self) -> str:
        """
        Returns a string representing the IP address
        corresponding to the server of the domain name.
        Returns an empty string if 'ip_address' is not available.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('ip_address', '')

    def server(self) -> str:
        """
        Returns a string representing server banner of the domain's IP address.
        For example: "nginx/1.16.0".  "N/A" is returned if unavailable.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('server', NA)

    def content_type(self) -> str:
        """
        Returns a string representing the MIME type of URL's content.
        For example "text/html; charset=UTF-8". 
        "N/A" is returned if unavailable.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('content_type', NA)

    def risk_score(self) -> int:
        """
        Returns an integer representing the The IPQS risk score which estimates
        the confidence level for malicious URL detection. Risk Scores 85+ are
        high risk, while Risk Scores = 100 are confirmed as accurate.  If no
        risk score exists, then DOES_NOT_EXIST will be returned.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('risk_score', DOES_NOT_EXIST)

    def status_code(self) -> int:
        """
        Returns an integer representing the HTTP Status Code of the URL's
        response. This value should be 200 for a valid website.
        0 is returned if URL is unreachable.

        Parameters
        ----------
        None.
        """
        return self.results.get('status_code', 0)

    def page_size(self) -> int:
        """
        Returns an integer representing the Total number of bytes to download
        the URL's content. 0 is returned if URL is unreachable.

        Parameters
        ----------
        None.
        """
        return self.results.get('page_size', 0)

    def domain_rank(self) -> int:
        """
        Returns an integer representing the estimated popularity rank of
        website globally. Returns 0 if the domain is unranked or has low
        traffic.  Returns DOES_NOT_EXIST if unreachable.

        Parameters
        ----------
        None.
        """
        return self.results.get('domain_rank', DOES_NOT_EXIST)

    def dns_valid(self) -> bool:
        """
        Returns boolean value indicating if the domain of the URL has valid
        DNS records.

        Parameters
        ----------
        None.
        """
        return bool(self.results.get('dns_valid'))

    def suspicious(self) -> bool:
        """
        Returns boolean value indicating if the URL is suspected of being
        malicious or used for phishing or abuse. Use in conjunction with
        the risk_score() method as a confidence level.

        Parameters
        ----------
        None.
        """
        return bool(self.results.get('suspicious'))

    def phishing(self) -> bool:
        """
        Returns boolean value indicating if the URL is
        associated with malicious phishing behavior.

        Parameters
        ----------
        None.
        """
        return bool(self.results.get('phishing'))

    def malware(self) -> bool:
        """
        Returns boolean value indicating if the URL is
        associated with malware or viruses.

        Parameters
        ----------
        None.
        """
        return bool(self.results.get('malware'))

    def parking(self) -> bool:
        """
        Returns boolean value indicating if the URL is
        currently parked with a for sale notice.

        Parameters
        ----------
        None.
        """
        return bool(self.results.get('parking'))

    def spamming(self) -> bool:
        """
        Returns boolean value indicating if the URL is
        associated with email SPAM or abusive email addresses.

        Parameters
        ----------
        None.
        """
        return bool(self.results.get('spamming'))

    def adult(self) -> bool:
        """
        Returns boolean value indicating if the URL or
        domain is hosting dating or adult content.

        Parameters
        ----------
        None.
        """
        return bool(self.results.get('adult'))

    def category(self) -> str:
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
        return self.results.get('category', NA)

    def domain_age(self) -> Dict[str, str]:
        """
        Returns a dictionary representing the domain age of the URL.
        If 'domain_age' is not available, then an empty dictionary
        will be returned.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('domain_age', {})

    def message(self) -> str:
        """
        Returns a generic status message, either success or
        some form of an error notice.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('message', '')

    def success(self) -> bool:
        """
        Returns a boolean indicating if the request to IPQS was successful.
        
        Parameters
        ----------
        None.
        """
        return bool(self.results.get('success'))

    def request_id(self) -> str:
        """
        Returns a string representing the unique identifier for this request
        that can be used to lookup the request details or send a postback
        conversion notice.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('request_id', '')

    def errors(self) -> List[str]:
        """
        Returns a list of strings representing the errors which
        occurred while attempting to process this request.
        
        Parameters
        ----------
        None.
        """
        return self.results.get('errors', [])

    def _is_valid_url(self, url: str) -> bool:
        is_valid = validate_url(url)

        if isinstance(is_valid, ValidationFailure):
            return False

        return is_valid

    def _no_results(self, status_code: int, message: str) -> Dict[str, object]:
        return {
            "success": False,
            "message": message,
            "status_code": status_code
        }
