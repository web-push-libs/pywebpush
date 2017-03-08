import base64
import json
import os
import unittest

from mock import patch, Mock
from nose.tools import eq_, ok_, assert_raises
import http_ece
import pyelliptic

from pywebpush import WebPusher, WebPushException, CaseInsensitiveDict, webpush


class WebpushTestCase(unittest.TestCase):

    # This is a exported DER formatted string of an ECDH public key
    # This was lifted from the py_vapid tests.
    vapid_key = (
        "MHcCAQEEIPeN1iAipHbt8+/KZ2NIF8NeN24jqAmnMLFZEMocY8RboAoGCCqGSM49"
        "AwEHoUQDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hbWAUpQFKDByKB81yldJ9GTklB"
        "M5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ=="
    )

    def _gen_subscription_info(self, recv_key,
                               endpoint="https://example.com/"):
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
        for content_encoding in ["aesgcm", "aes128gcm"]:
            recv_key = pyelliptic.ECC(curve="prime256v1")
            subscription_info = self._gen_subscription_info(recv_key)
            data = "Mary had a little lamb, with some nice mint jelly"
            push = WebPusher(subscription_info)
            encoded = push.encode(data, content_encoding=content_encoding)
            keyid = base64.urlsafe_b64encode(recv_key.get_pubkey()[1:])
            http_ece.keys[keyid] = recv_key
            http_ece.labels[keyid] = 'P-256'
            # Convert these b64 strings into their raw, binary form.
            raw_salt = None
            if 'salt' in encoded:
                raw_salt = base64.urlsafe_b64decode(
                    push._repad(encoded['salt']))
            raw_dh = base64.urlsafe_b64decode(
                push._repad(encoded['crypto_key']))
            raw_auth = base64.urlsafe_b64decode(
                push._repad(subscription_info['keys']['auth']))

            decoded = http_ece.decrypt(
                encoded['body'],
                salt=raw_salt,
                dh=raw_dh,
                keyid=keyid,
                authSecret=raw_auth,
                version=content_encoding
                )
            eq_(decoded.decode('utf8'), data)

    def test_bad_content_encoding(self):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        data = "Mary had a little lamb, with some nice mint jelly"
        push = WebPusher(subscription_info)
        self.assertRaises(WebPushException,
                          push.encode,
                          data,
                          content_encoding="aesgcm128")

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
        eq_(pheaders.get('ttl'), '0')
        ok_('encryption' in pheaders)
        eq_(pheaders.get('AUTHENTICATION'), headers.get('Authentication'))
        ckey = pheaders.get('crypto-key')
        ok_('pre-existing' in ckey)
        eq_(pheaders.get('content-encoding'), 'aesgcm')

    @patch("requests.post")
    def test_send_vapid(self, mock_post):
        mock_post.return_value = Mock()
        mock_post.return_value.status_code = 200
        recv_key = pyelliptic.ECC(curve="prime256v1")

        subscription_info = self._gen_subscription_info(recv_key)
        data = "Mary had a little lamb"
        webpush(
            subscription_info=subscription_info,
            data=data,
            vapid_private_key=self.vapid_key,
            vapid_claims={"sub": "mailto:ops@example.com"}
        )
        eq_(subscription_info.get('endpoint'), mock_post.call_args[0][0])
        pheaders = mock_post.call_args[1].get('headers')
        eq_(pheaders.get('ttl'), '0')

        def repad(str):
            return str + "===="[:len(str) % 4]

        auth = json.loads(
            base64.urlsafe_b64decode(
                repad(pheaders['authorization'].split('.')[1])
            ).decode('utf8')
        )
        ok_(subscription_info.get('endpoint').startswith(auth['aud']))
        ok_('encryption' in pheaders)
        ok_('WebPush' in pheaders.get('authorization'))
        ckey = pheaders.get('crypto-key')
        ok_('p256ecdsa=' in ckey)
        ok_('dh=' in ckey)
        eq_(pheaders.get('content-encoding'), 'aesgcm')

    @patch("requests.post")
    def test_send_bad_vapid_no_key(self, mock_post):
        mock_post.return_value = Mock()
        mock_post.return_value.status_code = 200
        recv_key = pyelliptic.ECC(curve="prime256v1")

        subscription_info = self._gen_subscription_info(recv_key)
        data = "Mary had a little lamb"
        assert_raises(WebPushException,
                      webpush,
                      subscription_info=subscription_info,
                      data=data,
                      vapid_claims={
                              "aud": "https://example.com",
                              "sub": "mailto:ops@example.com"
                          }
                      )

    @patch("requests.post")
    def test_send_bad_vapid_bad_return(self, mock_post):
        mock_post.return_value = Mock()
        mock_post.return_value.status_code = 410
        recv_key = pyelliptic.ECC(curve="prime256v1")

        subscription_info = self._gen_subscription_info(recv_key)
        data = "Mary had a little lamb"
        assert_raises(WebPushException,
                      webpush,
                      subscription_info=subscription_info,
                      data=data,
                      vapid_claims={
                              "aud": "https://example.com",
                              "sub": "mailto:ops@example.com"
                          },
                      vapid_private_key=self.vapid_key
                      )

    @patch("requests.post")
    def test_send_empty(self, mock_post):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        WebPusher(subscription_info).send('', headers)
        eq_(subscription_info.get('endpoint'), mock_post.call_args[0][0])
        pheaders = mock_post.call_args[1].get('headers')
        eq_(pheaders.get('ttl'), '0')
        ok_('encryption' not in pheaders)
        eq_(pheaders.get('AUTHENTICATION'), headers.get('Authentication'))
        ckey = pheaders.get('crypto-key')
        ok_('pre-existing' in ckey)

    def test_encode_empty(self):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        encoded = WebPusher(subscription_info).encode('', headers)
        eq_(encoded, None)

    def test_encode_no_crypto(self):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        del(subscription_info['keys'])
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        data = 'Something'
        pusher = WebPusher(subscription_info)
        assert_raises(WebPushException,
                      pusher.encode,
                      data,
                      headers)

    @patch("requests.post")
    def test_send_no_headers(self, mock_post):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        data = "Mary had a little lamb"
        WebPusher(subscription_info).send(data)
        eq_(subscription_info.get('endpoint'), mock_post.call_args[0][0])
        pheaders = mock_post.call_args[1].get('headers')
        eq_(pheaders.get('ttl'), '0')
        ok_('encryption' in pheaders)
        eq_(pheaders.get('content-encoding'), 'aesgcm')

    @patch("pywebpush.open")
    def test_as_curl(self, opener):
        recv_key = pyelliptic.ECC(curve="prime256v1")
        subscription_info = self._gen_subscription_info(recv_key)
        result = webpush(
            subscription_info,
            data="Mary had a little lamb",
            vapid_claims={
                    "aud": "https://example.com",
                    "sub": "mailto:ops@example.com"
                },
            vapid_private_key=self.vapid_key,
            curl=True
        )
        for s in [
            "curl -vX POST https://example.com",
            "-H \"crypto-key: p256ecdsa=",
            "-H \"content-encoding: aesgcm\"",
            "-H \"authorization: WebPush ",
            "-H \"encryption: keyid=p256dh;salt=",
            "-H \"ttl: 0\"",
            "-H \"content-length:"
        ]:
            ok_(s in result)

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
        wp.send(data, headers, gcm_key="gcm_key_value")
        pdata = json.loads(mock_post.call_args[1].get('data'))
        pheaders = mock_post.call_args[1].get('headers')
        eq_(pdata["registration_ids"][0], "regid123")
        eq_(pheaders.get("authorization"), "key=gcm_key_value")
        eq_(pheaders.get("content-type"), "application/json")
