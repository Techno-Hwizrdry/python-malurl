# python-malurl
A Python 3 module that leverages the IP Quality Score API to scan links in real-time to detect suspicious URLs.

## Prerequisites
This module requires python3 (version 3.6 or later) and python3-pip.

These prerequisites can be installed on a Debian based linux machine, like so:

`sudo apt-get install python3 python3-pip`

You will also need an API key from IP Quality Score to use this module.  You can sign up for one [here.](https://www.ipqualityscore.com/create-account)

## Installing

Via Python pip:

`pip install malurl`

## Usage
Import the MalURL object, like so:

`from malurl import MalURL`

Instantiatie a MalURL, with your IP Quality Score API key, like so:

`mal = MalURL(api_key)`

Strictness is set to 0 by default, if not provided.  It can be supplied with the MalURL constructor:

`mal = MalURL(api_key, strictness=1)`

Valid values for strictness are 0, 1, or 2.  Refer to the [IP Quality Score API doc](https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview) for more information on strictness.

Next, fetch the data of the desired URL from IP Quality Score API:

`mal.fetch('https://example.com')`

To conserve the amount of calls made to the API, the results (if any) will be stored within the MalURL object.  After that, the following methods can be called to retrieve the data that was obtained from the API call.

## Methods

#### \__init__(apikey: str, strictness: int = 0)
Constructor for MalURL object.

#### adult()
Returns boolean value indicating if the URL or
domain is hosting dating or adult content.

#### category()
Returns a string representing the website classification and category
related to the content and industry of the site. Over 70 categories
are available including “Video Streaming”, “Trackers”, “Gaming”,
“Privacy”, “Advertising”, “Hacking”, “Malicious”, “Phishing”, etc.
The value returned will be “N/A” if unknown.

#### content_type()
Returns a string representing the MIME type of URL’s content.
For example “text/html; charset=UTF-8”. 
“N/A” is returned if unavailable.

#### dns_valid()
Returns boolean value indicating if the domain of the URL has valid
DNS records.

#### domain()
Returns a string representing the domain name of the final
destination URL of the scanned link, after following all redirects.
Returns an empty string if ‘domain’ is not available.

#### domain_age()
Returns a dictionary representing the domain age of the URL.
If ‘domain_age’ is not available, then an empty dictionary
will be returned.

#### domain_rank()
Returns an integer representing the estimated popularity rank of
website globally. Returns 0 if the domain is unranked or has low
traffic.  Returns DOES_NOT_EXIST if unreachable.

#### errors()
Returns a list of strings representing the errors which
occurred while attempting to process this request.

#### fetch(url: str)
Sets self.results to a dictionary representing the JSON response
from IP Quality Score.  The url parameter will be validated
before a request to IP Quality Score is made.  This is done
to conserve our monthly request limit, in case url is invalid.

#### ip_address()
Returns a string representing the IP address
corresponding to the server of the domain name.
Returns an empty string if ‘ip_address’ is not available.

#### malware()
Returns boolean value indicating if the URL is
associated with malware or viruses.

#### message()
Returns a generic status message, either success or
some form of an error notice.

#### page_size()
Returns an integer representing the Total number of bytes to download
the URL’s content. 0 is returned if URL is unreachable.

#### parking()
Returns boolean value indicating if the URL is
currently parked with a for sale notice.

#### phishing()
Returns boolean value indicating if the URL is
associated with malicious phishing behavior.

#### print(rainbow: bool = False)
Output a limited amount of fields to standard output.

#### request_id()
Returns a string representing the unique identifier for this request
that can be used to lookup the request details or send a postback
conversion notice.

#### risk_score()
Returns an integer representing the The IPQS risk score which estimates
the confidence level for malicious URL detection. Risk Scores 85+ are
high risk, while Risk Scores = 100 are confirmed as accurate.  If no
risk score exists, then DOES_NOT_EXIST will be returned.

#### server()
Returns a string representing server banner of the domain’s IP address.
For example: “nginx/1.16.0”.  “N/A” is returned if unavailable.

#### spamming()
Returns boolean value indicating if the URL is
associated with email SPAM or abusive email addresses.

#### status_code()
Returns an integer representing the HTTP Status Code of the URL’s
response. This value should be 200 for a valid website.
0 is returned if URL is unreachable.

#### success()
Returns a boolean indicating if the request to IPQS was successful.

#### suspicious()
Returns boolean value indicating if the URL is suspected of being
malicious or used for phishing or abuse. Use in conjunction with
the risk_score() method as a confidence level.

#### unsafe()
Returns boolean value indicating if the domain is suspected of
being unsafe due to phishing, malware, spamming, or abusive
behavior. View the confidence level by analyzing the “risk_score”.
