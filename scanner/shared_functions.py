# python3

import urllib.request
import sys
import os
import json


def default_value(desired_type):
    if desired_type == str:
        return ''
    elif desired_type == int:
        return -1
    elif desired_type == float:
        return -1.0
    elif desired_type == bool:
        return ''

    print('Unsupported type: %s' % str(desired_type), file=sys.stderr)


def return_json_value(obj, expected_type):
    try:
        if callable(obj):
            obj = obj()

        if type(obj) == expected_type:
                return obj
        else:
            raise ValueError('Type %s expected, %s given' % (str(expected_type), str(type(obj))))

    except Exception as e:
        print(e, file=sys.stderr)


def write_json(path, data):
    if os.path.exists(path):
        os.remove(path)

    with open(path, 'w') as dump:
        json.dump(data, dump, indent=2)


def read_json(path):
    with open(path) as f:
        return json.load(f)


def fetch(url, error_msg, is_json=True):
    request = urllib.request.Request(url)
    request.add_header('Version', '1.1')
    request.add_header('Accept',  '*/json')
    request.add_header('User-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0')

    response = urllib.request.urlopen(request)

    if is_json:
        try:
            content = json.loads(response.read().decode('utf-8'))
            if content.get('status') != 'success':
                raise Exception()
        except Exception as e:
            print(e, file=sys.stderr)
            raise Exception(error_msg)

        return content.get('data')

    else:
        content = response.read()

        try:
            content = content.decode('UTF-8')
        except UnicodeDecodeError:
            content = content.decode('ISO-8859-1')

        return content
