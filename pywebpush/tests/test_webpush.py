import base64
import json
import os
import unittest
import time

from mock import patch, Mock
import http_ece
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import py_vapid

from pywebpush import WebPusher, WebPushException, CaseInsensitiveDict, webpush


class WebpushTestCase(unittest.TestCase):

    # This is a exported DER formatted string of an ECDH public key
    # This was lifted from the py_vapid tests.
    vapid_key = (
        "MHcCAQEEIPeN1iAipHbt8+/KZ2NIF8NeN24jqAmnMLFZEMocY8RboAoGCCqGSM49"
        "AwEHoUQDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hbWAUpQFKDByKB81yldJ9GTklB"
        "M5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ=="
    )

    def _gen_subscription_info(self,
                               recv_key=None,
                               endpoint="https://example.com/"):
        if not recv_key:
            recv_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        return {
            "endpoint": endpoint,
            "keys": {
                'auth': base64.urlsafe_b64encode(os.urandom(16)).strip(b'='),
                'p256dh': self._get_pubkey_str(recv_key),
            }
        }

    def _get_pubkey_str(self, priv_key):
        return base64.urlsafe_b64encode(
            priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )).strip(b'=')

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
        assert push.subscription_info != subscription_info
        assert push.subscription_info['keys'] != subscription_info['keys']
        assert push.subscription_info['endpoint'] == subscription_info['endpoint']
        assert push.receiver_key == rk_decode
        assert push.auth_key == b'\x93\xc2U\xea\xc8\xddn\x10"\xd6}\xff,0K\xbc'

    def test_encode(self):
        for content_encoding in ["aesgcm", "aes128gcm"]:
            recv_key = ec.generate_private_key(
                ec.SECP256R1, default_backend())
            subscription_info = self._gen_subscription_info(recv_key)
            data = "Mary had a little lamb, with some nice mint jelly"
            push = WebPusher(subscription_info)
            encoded = push.encode(data, content_encoding=content_encoding)
            """
            crypto_key = base64.urlsafe_b64encode(
                self._get_pubkey_str(recv_key)
            ).strip(b'=')
            """
            # Convert these b64 strings into their raw, binary form.
            raw_salt = None
            if 'salt' in encoded:
                raw_salt = base64.urlsafe_b64decode(
                    push._repad(encoded['salt']))
            raw_dh = None
            if content_encoding != "aes128gcm":
                raw_dh = base64.urlsafe_b64decode(
                    push._repad(encoded['crypto_key']))
            raw_auth = base64.urlsafe_b64decode(
                push._repad(subscription_info['keys']['auth']))
            decoded = http_ece.decrypt(
                encoded['body'],
                salt=raw_salt,
                dh=raw_dh,
                private_key=recv_key,
                auth_secret=raw_auth,
                version=content_encoding
                )
            assert decoded.decode('utf8') == data

    def test_bad_content_encoding(self):
        subscription_info = self._gen_subscription_info()
        data = "Mary had a little lamb, with some nice mint jelly"
        push = WebPusher(subscription_info)
        self.assertRaises(WebPushException,
                          push.encode,
                          data,
                          content_encoding="aesgcm128")

    @patch("requests.post")
    def test_send(self, mock_post):
        subscription_info = self._gen_subscription_info()
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        data = "Mary had a little lamb"
        WebPusher(subscription_info).send(data, headers)
        assert subscription_info.get('endpoint') == mock_post.call_args[0][0]
        pheaders = mock_post.call_args[1].get('headers')
        assert pheaders.get('ttl') == '0'
        assert pheaders.get('AUTHENTICATION') == headers.get('Authentication')
        ckey = pheaders.get('crypto-key')
        assert 'pre-existing' in ckey
        assert pheaders.get('content-encoding') == 'aes128gcm'

    @patch("requests.post")
    def test_send_vapid(self, mock_post):
        mock_post.return_value.status_code = 200
        subscription_info = self._gen_subscription_info()
        data = "Mary had a little lamb"
        webpush(
            subscription_info=subscription_info,
            data=data,
            vapid_private_key=self.vapid_key,
            vapid_claims={"sub": "mailto:ops@example.com"},
            content_encoding="aesgcm",
            headers={"Test-Header": "test-value"}
        )
        assert subscription_info.get('endpoint') == mock_post.call_args[0][0]
        pheaders = mock_post.call_args[1].get('headers')
        assert pheaders.get('ttl') == '0'

        def repad(str):
            return str + "===="[:len(str) % 4]

        auth = json.loads(
            base64.urlsafe_b64decode(
                repad(pheaders['authorization'].split('.')[1])
            ).decode('utf8')
        )
        assert subscription_info.get('endpoint').startswith(auth['aud'])
        assert 'vapid' in pheaders.get('authorization')
        ckey = pheaders.get('crypto-key')
        assert 'dh=' in ckey
        assert pheaders.get('content-encoding') == 'aesgcm'
        assert pheaders.get('test-header') == 'test-value'

    @patch.object(WebPusher, "send")
    @patch.object(py_vapid.Vapid, "sign")
    def test_webpush_vapid_instance(self, vapid_sign, pusher_send):
        pusher_send.return_value.status_code = 200
        subscription_info = self._gen_subscription_info()
        data = "Mary had a little lamb"
        vapid_key = py_vapid.Vapid.from_string(self.vapid_key)
        claims = dict(sub="mailto:ops@example.com", aud="https://example.com")
        webpush(
            subscription_info=subscription_info,
            data=data,
            vapid_private_key=vapid_key,
            vapid_claims=claims,
        )
        vapid_sign.assert_called_once_with(claims)
        pusher_send.assert_called_once()

    @patch.object(WebPusher, "send")
    @patch.object(py_vapid.Vapid, "sign")
    def test_webpush_vapid_exp(self, vapid_sign, pusher_send):
        pusher_send.return_value.status_code = 200
        subscription_info = self._gen_subscription_info()
        data = "Mary had a little lamb"
        vapid_key = py_vapid.Vapid.from_string(self.vapid_key)
        claims = dict(sub="mailto:ops@example.com",
                      aud="https://example.com",
                      exp=int(time.time() - 48600))
        webpush(
            subscription_info=subscription_info,
            data=data,
            vapid_private_key=vapid_key,
            vapid_claims=claims,
        )
        vapid_sign.assert_called_once_with(claims)
        pusher_send.assert_called_once()
        assert claims['exp'] > int(time.time())

    @patch("requests.post")
    def test_send_bad_vapid_no_key(self, mock_post):
        mock_post.return_value.status_code = 200

        subscription_info = self._gen_subscription_info()
        data = "Mary had a little lamb"
        self.assertRaises(
            WebPushException,
            webpush,
            subscription_info=subscription_info,
            data=data,
            vapid_claims={
                "aud": "https://example.com",
                "sub": "mailto:ops@example.com"
            })

    @patch("requests.post")
    def test_send_bad_vapid_bad_return(self, mock_post):
        mock_post.return_value.status_code = 410

        subscription_info = self._gen_subscription_info()
        data = "Mary had a little lamb"
        self.assertRaises(
            WebPushException,
            webpush,
            subscription_info=subscription_info,
            data=data,
            vapid_claims={
                "aud": "https://example.com",
                "sub": "mailto:ops@example.com"
            },
            vapid_private_key=self.vapid_key)

    @patch("requests.post")
    def test_send_empty(self, mock_post):
        subscription_info = self._gen_subscription_info()
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        WebPusher(subscription_info).send('', headers)
        assert subscription_info.get('endpoint') == mock_post.call_args[0][0]
        pheaders = mock_post.call_args[1].get('headers')
        assert pheaders.get('ttl') == '0'
        assert 'encryption' not in pheaders
        assert pheaders.get('AUTHENTICATION') == headers.get('Authentication')
        ckey = pheaders.get('crypto-key')
        assert 'pre-existing' in ckey

    def test_encode_empty(self):
        subscription_info = self._gen_subscription_info()
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        encoded = WebPusher(subscription_info).encode('', headers)
        assert encoded is None

    def test_encode_no_crypto(self):
        subscription_info = self._gen_subscription_info()
        del(subscription_info['keys'])
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        data = 'Something'
        pusher = WebPusher(subscription_info)
        self.assertRaises(
            WebPushException,
            pusher.encode,
            data,
            headers)

    @patch("requests.post")
    def test_send_no_headers(self, mock_post):
        subscription_info = self._gen_subscription_info()
        data = "Mary had a little lamb"
        WebPusher(subscription_info).send(data)
        assert subscription_info.get('endpoint') == mock_post.call_args[0][0]
        pheaders = mock_post.call_args[1].get('headers')
        assert pheaders.get('ttl') == '0'
        assert pheaders.get('content-encoding') == 'aes128gcm'

    @patch("pywebpush.open")
    def test_as_curl(self, opener):
        subscription_info = self._gen_subscription_info()
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
            "-H \"content-encoding: aes128gcm\"",
            "-H \"authorization: vapid ",
            "-H \"ttl: 0\"",
            "-H \"content-length:"
        ]:
            assert s in result, "missing: {}".format(s)

    def test_ci_dict(self):
        ci = CaseInsensitiveDict({"Foo": "apple", "bar": "banana"})
        assert 'apple' == ci["foo"]
        assert 'apple' == ci.get("FOO")
        assert 'apple' == ci.get("Foo")
        del (ci['FOO'])
        assert ci.get('Foo') is None

    @patch("requests.post")
    def test_gcm(self, mock_post):
        subscription_info = self._gen_subscription_info(
            None,
            endpoint="https://android.googleapis.com/gcm/send/regid123")
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        data = "Mary had a little lamb"
        wp = WebPusher(subscription_info)
        wp.send(data, headers, gcm_key="gcm_key_value")
        pdata = json.loads(mock_post.call_args[1].get('data'))
        pheaders = mock_post.call_args[1].get('headers')
        assert pdata["registration_ids"][0] == "regid123"
        assert pheaders.get("authorization") == "key=gcm_key_value"
        assert pheaders.get("content-type") == "application/json"

    @patch("requests.post")
    def test_timeout(self, mock_post):
        mock_post.return_value.status_code = 200
        subscription_info = self._gen_subscription_info()
        WebPusher(subscription_info).send(timeout=5.2)
        assert mock_post.call_args[1].get('timeout') == 5.2
        webpush(subscription_info, timeout=10.001)
        assert mock_post.call_args[1].get('timeout') == 10.001

    @patch("requests.Session")
    def test_send_using_requests_session(self, mock_session):
        subscription_info = self._gen_subscription_info()
        headers = {"Crypto-Key": "pre-existing",
                   "Authentication": "bearer vapid"}
        data = "Mary had a little lamb"
        WebPusher(subscription_info,
                  requests_session=mock_session).send(data, headers)
        assert subscription_info.get(
            'endpoint') == mock_session.post.call_args[0][0]
        pheaders = mock_session.post.call_args[1].get('headers')
        assert pheaders.get('ttl') == '0'
        assert pheaders.get('AUTHENTICATION') == headers.get('Authentication')
        ckey = pheaders.get('crypto-key')
        assert 'pre-existing' in ckey
        assert pheaders.get('content-encoding') == 'aes128gcm'


class WebpushExceptionTestCase(unittest.TestCase):

    def test_exception(self):
        from requests import Response

        exp = WebPushException("foo")
        assert ("{}".format(exp) == "WebPushException: foo")
        # Really should try to load the response to verify, but this mock
        # covers what we need.
        response = Mock(spec=Response)
        response.text = (
             '{"code": 401, "errno": 109, "error": '
             '"Unauthorized", "more_info": "http://'
             'autopush.readthedocs.io/en/latest/htt'
             'p.html#error-codes", "message": "Requ'
             'est did not validate missing authoriz'
             'ation header"}')
        response.json.return_value = json.loads(response.text)
        response.status_code = 401
        response.reason = "Unauthorized"
        exp = WebPushException("foo", response)
        assert "{}".format(exp) == "WebPushException: foo, Response {}".format(
                response.text)
        assert '{}'.format(exp.response), '<Response [401]>'
        assert exp.response.json().get('errno') == 109
        exp = WebPushException("foo", [1, 2, 3])
        assert '{}'.format(exp) == "WebPushException: foo, Response [1, 2, 3]"
