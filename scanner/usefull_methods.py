#python3

from xml.parsers import expat
import urllib.request
import os
import requests
import sys
import json

#
#
#       Usefull Methods
#
#

def log_activity(log_string):
    pass

def default_value(value_type):
    if value_type == str:
        return ""
    if value_type == int:
        return -1
    if value_type == float:
        return -1.0
    if value_type == bool:
        return ""

    print("type not found:%s" % str(value_type))


def return_json_value(obj, expected_type):
    global default_value
    try:
        return_value = obj

        if callable(obj):
                return_value = obj()

        if type(return_value) == expected_type:
                return return_value

        raise ValueError(ERROR_STRING)
    except:
        return default_value(expected_type)


def write_json(fname, dict):
    if os.path.exists(fname):
        os.remove(fname)

    with open(fname, 'w') as dump:
        json.dump(dict, dump, indent=2)


def read_json(fname):
    with open(fname) as f:
        data = json.load(f)
    return data


def fetch(url, error_msg, is_json=True):
    request = urllib.request.Request(url)
    request.add_header('Version', '1.1')
    request.add_header('Accept',  '*/json')
    request.add_header('User-agent',
            "Mozilla/5.0 (X11; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0")

    response = urllib.request.urlopen(request)

    if is_json:
        try:
            content = json.loads(response.read().decode("utf-8"))
            if content.get("status") != "success":
                raise Exception()
        except Exception as e:
            print (e)
            raise Exception(error_msg)

        return content.get("data")

    else:
        content = response.read()

        try:
            content = content.decode('UTF-8')
        except UnicodeDecodeError:
            content = content.decode('ISO-8859-1')

        return content
