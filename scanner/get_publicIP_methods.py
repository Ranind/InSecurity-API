#python 3

#fetch
import re
from usefull_methods import *

#
#
#       Get Public IP Methods
#
#

def get_public_ip():
        urls = ['http://ip.dnsexit.com',
                'http://ifconfig.me/ip',
                'http://ipecho.net/plain',
                'http://checkip.dyndns.org/plain',
                'http://whatismyipaddress.com/',
                'http://websiteipaddress.com/WhatIsMyIp',
                'http://getmyipaddress.org/',
                'http://www.my-ip-address.net/',
                'http://myexternalip.com/raw',
                'http://www.canyouseeme.org/',
                'http://www.trackip.net/',
                'http://icanhazip.com/',
                'http://www.iplocation.net/',
                'http://www.howtofindmyipaddress.com/',
                'http://www.ipchicken.com/',
                'http://whatsmyip.net/',
                'http://www.ip-adress.com/',
                'http://checkmyip.com/',
                'http://www.tracemyip.org/',
                'http://www.lawrencegoetz.com/programs/ipinfo/',
                'http://www.findmyip.co/',
                'http://ip-lookup.net/',
                'http://www.dslreports.com/whois',
                'http://www.mon-ip.com/en/my-ip/',
                'http://www.myip.ru',
                'http://ipgoat.com/',
                'http://www.myipnumber.com/my-ip-address.asp',
                'http://www.whatsmyipaddress.net/',
                'http://formyip.com/',
                'https://check.torproject.org/',
                'http://www.displaymyip.com/',
                'http://www.bobborst.com/tools/whatsmyip/',
                'http://checkip.dyndns.com/',
                'http://myexternalip.com/',
                'http://www.ip-adress.eu/',
                'http://www.infosniper.net/',
                'https://wtfismyip.com/text',
                'http://ipinfo.io/',
                'http://httpbin.org/ip',
                'https://diagnostic.opendns.com/myip']
        public_ip = ""
        error_msg = "Error in get_public_ip"

        for url in urls:
            public_ip = extract_ip_from_response(fetch(url,error_msg,is_json=False))
            if public_ip != "": return public_ip
        return ""


def extract_ip_from_response(response):
    pattern = '(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\.){3}' + \
              '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

    try:
        regx = re.search(pattern, response)
        ip = regx.group(0)
        if len(ip) > 0:
            return ip
            return ''
    except Exception:
        return ''
