# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import os

import http_ece
import pyelliptic

VAPID = True

try:
    # from https://github.com/mozilla-services/vapid/tree/master/python
    from py_vapid import Vapid
except ImportError:
    VAPID = False


class WebPushException(Exception):
    pass


class WebPusher:

    def __init__(self, keys):
        for k in ['p256dh', 'auth']:
            if keys.get(k) is None:
                raise WebPushException("Missing keys value: %s", k)
        receiverRaw = base64.urlsafe_b64decode(self._repad(keys['p256dh']))
        if len(receiverRaw) != 65 and receiverRaw[0] != "\x04":
            raise WebPushException("Invalid p256dh key specified")
        self.receiverKey = receiverRaw
        self.authKey = base64.urlsafe_b64decode(self._repad(keys['auth']))

    def _repad(self, str):
        return str + "===="[:len(str) % 4]

    def encode(self, data):
        # Salt is a random 16 byte array.
        salt = os.urandom(16)
        # The server key is an ephemeral ECDH key used only for this
        # transaction
        serverKey = pyelliptic.ECC(curve="prime256v1")
        # the ID is the base64 of the raw key, minus the leading "\x04"
        # ID tag.
        serverKeyID = base64.urlsafe_b64encode(serverKey.get_pubkey()[1:])
        http_ece.keys[serverKeyID] = serverKey
        http_ece.labels[serverKeyID] = "P-256"

        encrypted = http_ece.encrypt(
            data,
            salt=salt,
            keyid=serverKeyID,
            dh=self.receiverKey,
            authSecret=self.authKey)

        return {
            'cryptokey': base64.urlsafe_b64encode(
                serverKey.get_pubkey()).strip('='),
            'salt': base64.urlsafe_b64encode(salt).strip("="),
            'body': encrypted,
        }

    def to_curl(self, endpoint, encode, headers={}, dataFile="encrypted.data"):
        cryptokey = "keyid=p256dh;dh=%s" % encoded.get("cryptokey")
        if headers.get('crypto-key'):
            cryptokey = headers.get('crypto-key') + ','
        headers["crypto-key"] = headers.get("crypto-key", "") + cryptokey
        headers["TTL"] = 60
        headers["content-encoding"] = "aesgcm"
        headers["encryption"] = "keyid=p256dh;salt=%s" % encoded.get("salt")
        reply = "curl -v -X POST %s " % endpoint
        for key in headers:
            reply += """-H "%s: %s" """ % (key, headers.get(key))
        if dataFile:
            reply += "--data-binary @%s" % dataFile
        return reply


if __name__ == "__main__":

    # The client provides the following values:
    endpoint = ("https://updates.push.services.mozilla.com/push/v1/gAAAAABXAuZ"
                "mKfEEyPbYfLXqtPW-yblFhEj-wjW5XHPJ3SMqjv9LlDWOAY9ljyZ80R4xHfD8"
                "x2D_20j5mH4nbRQFyyCS33uyLgTp56zizeaitkMsw5EoAM8sRN_fz0Aaezrk9"
                "W5uKpaf")
    keys = {
        "p256dh": ("BOrnIslXrUow2VAzKCUAE4sIbK00daEZCswOcf8m3T"
                   "F8V82B-OpOg5JbmYLg44kRcvQC1E2gMJshsUYA-_zMPR8"),
        "auth": "k8JV6sjdbhAi1n3_LDBLvA",
    }

    # This is the optional VAPID data

    vapid_claims = {
        "aud": "http://example.com",
        "sub": "mailto:admin@example.com",
        }

    data = "Mary had a little lamb, with a nice mint jelly."

    vapid_headers = {}
    if VAPID:
        # You should only generate keys once, and write them out to
        # safe storage. See https://github.com/mozilla-services/vapid for
        # details.
        vapid = Vapid()
        vapid.generate_keys()
        vapid_headers = vapid.sign(vapid_claims)

    push = WebPusher(keys=keys)
    encoded = push.encode(data)
    with open("encrypted.data", "w") as out:
        out.write(encoded.get('body'))

    print push.to_curl(endpoint, encoded, vapid_headers)
