# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import os

import http_ece
import pyelliptic
import requests


class WebPushException(Exception):
    pass


class WebPusher:
    """WebPusher encrypts a data block using HTTP Encrypted Content Encoding
    for WebPush.

    See https://tools.ietf.org/html/draft-ietf-webpush-protocol-04
    for the current specification, and
    https://developer.mozilla.org/en-US/docs/Web/API/Push_API for an
    overview of Web Push.

    Example of use:

    The javascript promise handler for PushManager.subscribe()
    receives a subscription_info object. subscription_info.getJSON()
    will return a JSON representation.
    (e.g.
    .. code-block:: javascript
        subscription_info.getJSON() ==
        {"endpoint": "https://push...",
         "keys":{"auth": "...", "p256dh": "..."}
        }
    )

    This subscription_info block can be stored.

    To send a subscription update:

    .. code-block:: python
        # Optional
        # headers = py_vapid.sign({"aud": "http://your.site.com",
                                   "sub": "mailto:your_admin@your.site.com"})
        data = "Mary had a little lamb, with a nice mint jelly"
        WebPusher(subscription_info).send(data, headers)

    """
    subscription_info = {}

    def __init__(self, subscription_info):
        """Initialize using the info provided by the client PushSubscription
        object (See
        https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe)

        :param subscription_info: a dict containing the subscription_info from
            the client.

        """
        if 'endpoint' not in subscription_info:
            raise WebPushException("subscription_info missing endpoint URL")
        if 'keys' not in subscription_info:
            raise WebPushException("subscription_info missing keys dictionary")
        self.subscription_info = subscription_info
        keys = self.subscription_info['keys']
        for k in ['p256dh', 'auth']:
            if keys.get(k) is None:
                raise WebPushException("Missing keys value: %s", k)
        receiver_raw = base64.urlsafe_b64decode(
            self._repad(keys['p256dh'].encode('utf8')))
        if len(receiver_raw) != 65 and receiver_raw[0] != "\x04":
            raise WebPushException("Invalid p256dh key specified")
        self.receiver_key = receiver_raw
        self.auth_key = base64.urlsafe_b64decode(
            self._repad(keys['auth'].encode('utf8')))

    def _repad(self, str):
        """Add base64 padding to the end of a string, if required"""
        return str + "===="[:len(str) % 4]

    def encode(self, data):
        """Encrypt the data.

        :param data: A serialized block of data (String, JSON, bit array,
            etc.) Make sure that whatever you send, your client knows how
            to understand it.

        """
        # Salt is a random 16 byte array.
        salt = os.urandom(16)
        # The server key is an ephemeral ECDH key used only for this
        # transaction
        server_key = pyelliptic.ECC(curve="prime256v1")
        # the ID is the base64 of the raw key, minus the leading "\x04"
        # ID tag.
        server_key_id = base64.urlsafe_b64encode(server_key.get_pubkey()[1:])

        # http_ece requires that these both be set BEFORE encrypt or
        # decrypt is called if you specify the key as "dh".
        http_ece.keys[server_key_id] = server_key
        http_ece.labels[server_key_id] = "P-256"

        encrypted = http_ece.encrypt(
            data,
            salt=salt,
            keyid=server_key_id,
            dh=self.receiver_key,
            authSecret=self.auth_key)

        return {
            'crypto_key': base64.urlsafe_b64encode(
                server_key.get_pubkey()).strip('='),
            'salt': base64.urlsafe_b64encode(salt).strip("="),
            'body': encrypted,
        }

    def send(self, data, headers={}, ttl=0):
        """Encode and send the data to the Push Service.

        :param data: A serialized block of data (see encode() ).
        :param headers: A dictionary containing any additional HTTP headers.
        :param ttl: The Time To Live in seconds for this message if the
            recipient is not online. (Defaults to "0", which discards the
            message immediately if the recipient is unavailable.)

        """
        # Encode the data.
        encoded = self.encode(data)
        # Append the p256dh to the end of any existing crypto-key
        crypto_key = headers.get("crypto-key", "")
        if crypto_key:
            crypto_key += ','
        crypto_key += "keyid=p256dh;dh=" + encoded["crypto_key"]
        headers.update({
            'crypto-key': crypto_key,
            'content-encoding': 'aesgcm',
            'encryption': "keyid=p256dh;salt=" + encoded['salt'],
        })
        if 'ttl' not in headers or ttl:
            headers['ttl'] = ttl
        # Additionally useful headers:
        # Authorization / Crypto-Key (VAPID headers)
        return requests.post(self.subscription_info['endpoint'],
                             data=encoded.get('body'),
                             headers=headers)
