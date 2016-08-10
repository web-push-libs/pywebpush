import base64
import json
import os
import unittest

import http_ece
from mock import patch
from nose.tools import eq_, ok_
import pyelliptic

from pywebpush import WebPusher, WebPushException, CaseInsensitiveDict


class WebpushTestCase(unittest.TestCase):
    def _gen_subscription_info(self, recv_key, endpoint="https://example.com"):
        return {
            "endpoint": endpoint,
            "keys": {
                'auth': base64.urlsafe_b64encode(os.urandom(16)).strip(b'='),
                'p256dh': base64.urlsafe_b64encode(
                    recv_key.get_pubkey()).strip(b'='),
            }
        }

    def test_init(self):
        # use static values so we know what to look for in the reply
        subscription_info = {
            u"endpoint": u"https://example.com/",
            u"keys": {
                u"p256dh": (u"BOrnIslXrUow2VAzKCUAE4sIbK00daEZCswOcf8m3T"
                            "F8V82B-OpOg5JbmYLg44kRcvQC1E2gMJshsUYA-_zMPR8"),
                u"auth": u"k8JV6sjdbhAi1n3_LDBLvA"
            }
        }
        rk_decode = (b'\x04\xea\xe7"\xc9W\xadJ0\xd9P3(%\x00\x13\x8b'
                     b'\x08l\xad4u\xa1\x19\n\xcc\x0eq\xff&\xdd1'
                     b'|W\xcd\x81\xf8\xeaN\x83\x92[\x99\x82\xe0\xe3'
                     b'\x89\x11r\xf4\x02\xd4M\xa00\x9b!\xb1F\x00'
                     b'\xfb\xfc\xcc=\x1f')
        self.assertRaises(
            WebPushException,
            WebPusher,
            {"keys": {'p256dh': 'AAA=', 'auth': 'AAA='}})
        self.assertRaises(
            WebPushException,
            WebPusher,
            {"endpoint": "https://example.com"})
        self.assertRaises(
            WebPushException,
            WebPusher,
            {"endpoint": "https://example.com", "keys": {'p256dh': 'AAA='}})
        self.assertRaises(
            WebPushException,
            WebPusher,
            {"endpoint": "https://example.com", "keys": {'auth': 'AAA='}})
        self.assertRaises(
            WebPushException,
            WebPusher,
            {"endpoint": "https://example.com",
             "keys": {'p256dh': 'AAA=', 'auth': 'AAA='}})

        push = WebPusher(subscription_info)
        eq_(push.subscription_info, subscription_info)
        eq_(push.receiver_key, rk_decode)
        eq_(push.auth_key, b'\x93\xc2U\xea\xc8\xddn\x10"\xd6}\xff,0K\xbc')

    def test_encode(self):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        data = "Mary had a little lamb, with some nice mint jelly"
        push = WebPusher(subscription_info)
        encoded = push.encode(data)

        keyid = base64.urlsafe_b64encode(recv_key.get_pubkey()[1:])

        http_ece.keys[keyid] = recv_key
        http_ece.labels[keyid] = 'P-256'

        # Convert these b64 strings into their raw, binary form.
        raw_salt = base64.urlsafe_b64decode(push._repad(encoded['salt']))
        raw_dh = base64.urlsafe_b64decode(push._repad(encoded['crypto_key']))
        raw_auth = base64.urlsafe_b64decode(
            push._repad(subscription_info['keys']['auth']))

        decoded = http_ece.decrypt(
            buffer=encoded['body'],
            salt=raw_salt,
            dh=raw_dh,
            keyid=keyid,
            authSecret=raw_auth
            )

        eq_(decoded.decode('utf8'), data)

    @patch("requests.post")
    def test_send(self, mock_post):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        data = "Mary had a little lamb"
        WebPusher(subscription_info).send(data, headers)
        eq_(subscription_info.get('endpoint'), mock_post.call_args[0][0])
        pheaders = mock_post.call_args[1].get('headers')
        eq_(pheaders.get('ttl'), 0)
        ok_('encryption' in pheaders)
        eq_(pheaders.get('AUTHENTICATION'), headers.get('Authentication'))
        ckey = pheaders.get('crypto-key')
        ok_('pre-existing' in ckey)
        eq_(pheaders.get('content-encoding'), 'aesgcm')

    def test_ci_dict(self):
        ci = CaseInsensitiveDict({"Foo": "apple", "bar": "banana"})
        eq_('apple', ci["foo"])
        eq_('apple', ci.get("FOO"))
        eq_('apple', ci.get("Foo"))
        del (ci['FOO'])
        eq_(None, ci.get('Foo'))

    @patch("requests.post")
    def test_gcm(self, mock_post):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(
            recv_key,
            endpoint="https://android.googleapis.com/gcm/send/regid123")
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        data = "Mary had a little lamb"
        wp = WebPusher(subscription_info)
        self.assertRaises(
            WebPushException,
            wp.send,
            data,
            headers)
        wp.send(data, headers, gcm_key="gcm_key_value")
        pdata = json.loads(mock_post.call_args[1].get('data'))
        pheaders = mock_post.call_args[1].get('headers')
        eq_(pdata["registration_ids"][0], "regid123")
        eq_(pheaders.get("authorization"), "key=gcm_key_value")
        eq_(pheaders.get("content-type"), "application/json")
