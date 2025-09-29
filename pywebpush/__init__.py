# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import asyncio
import base64
import json
import os
import time
import logging
from copy import deepcopy
from typing import cast, Union, Dict

try:
    from urlparse import urlparse
except ImportError:  # pragma nocover
    from urllib.parse import urlparse

import aiohttp
import http_ece
import requests
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from functools import partial
from py_vapid import Vapid, Vapid01
from requests import Response


class WebPushException(Exception):
    """Web Push failure.

    This may contain the requests.Response

    """

    def __init__(self, message, response=None):
        self.message = message
        self.response = response

    def __str__(self):
        extra = ""
        if self.response is not None:
            try:
                extra = ", Response {}".format(
                    self.response.text,
                )
            except AttributeError:
                extra = ", Response {}".format(self.response)
        return "WebPushException: {}{}".format(self.message, extra)


class NoData(Exception):
    """Message contained No Data, no encoding required."""


class CaseInsensitiveDict(dict):
    """A dictionary that has case-insensitive keys"""

    def __init__(self, data={}, **kwargs):
        for key in data:
            dict.__setitem__(self, key.lower(), data[key])
        self.update(kwargs)

    def __contains__(self, key):
        return dict.__contains__(self, key.lower())

    def __setitem__(self, key, value):
        dict.__setitem__(self, key.lower(), value)

    def __getitem__(self, key):
        return dict.__getitem__(self, key.lower())

    def __delitem__(self, key):
        dict.__delitem__(self, key.lower())

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def update(self, data):
        for key in data:
            self.__setitem__(key, data[key])


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
        {"endpoint": "https://push.server.com/...",
         "keys":{"auth": "...", "p256dh": "..."}
        }
    )

    This subscription_info block can be stored.

    To send a subscription update:

    .. code-block:: python
        # Optional
        # headers = py_vapid.sign({"aud": "https://push.server.com/",
                                   "sub": "mailto:your_admin@your.site.com"})
        data = "Mary had a little lamb, with a nice mint jelly"
        WebPusher(subscription_info).send(data, headers)

    """

    subscription_info = {}
    valid_encodings = [
        # "aesgcm128",  # this is draft-0, but DO NOT USE.
        "aesgcm",  # draft-httpbis-encryption-encoding-01
        "aes128gcm",  # RFC8188 Standard encoding
    ]
    verbose = False

    # Note: the type declarations are not valid under python 3.8,
    def __init__(
        self,
        subscription_info: Dict[
            str, Union[Union[str, bytes], Dict[str, Union[str, bytes]]]
        ],
        requests_session: Union[None, requests.Session] = None,
        aiohttp_session: Union[None, aiohttp.client.ClientSession] = None,
        verbose: bool = False,
    ):
        """Initialize using the info provided by the client PushSubscription
        object (See
        https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe)

        :param subscription_info: a dict containing the subscription_info from
            the client.
        :type subscription_info: dict

        :param requests_session: a requests.Session object to optimize requests
            to the same client.
        :type requests_session: requests.Session

        :param verbose: provide verbose feedback
        :type verbose: bool

        """

        self.verbose = verbose
        if requests_session is None:
            self.requests_method = requests
        else:
            self.requests_method = requests_session

        self.aiohttp_session = aiohttp_session

        if "endpoint" not in subscription_info:
            raise WebPushException("subscription_info missing endpoint URL")
        self.subscription_info = deepcopy(subscription_info)
        self.auth_key = self.receiver_key = None
        if "keys" in subscription_info:
            keys: Dict[str, Union[str, bytes]] = cast(
                Dict[str, Union[str, bytes]], self.subscription_info["keys"]
            )
            for k in ["p256dh", "auth"]:
                if keys.get(k) is None:
                    raise WebPushException("Missing keys value: {}".format(k))
                if isinstance(keys[k], six.text_type):
                    keys[k] = bytes(cast(str, keys[k]).encode("utf8"))
            receiver_raw = base64.urlsafe_b64decode(
                self._repad(cast(bytes, keys["p256dh"]))
            )
            if len(receiver_raw) != 65 and receiver_raw[0] != "\x04":
                raise WebPushException("Invalid p256dh key specified")
            self.receiver_key = receiver_raw
            self.auth_key = base64.urlsafe_b64decode(
                self._repad(cast(bytes, keys["auth"]))
            )

    def verb(self, msg: str, *args, **kwargs):
        if self.verbose:
            logging.info(msg.format(*args, **kwargs))

    def _repad(self, data: bytes):
        """Add base64 padding to the end of a string, if required"""
        return data + b"===="[: len(data) % 4]

    def encode(
        self, data: bytes, content_encoding: str = "aes128gcm"
    ) -> CaseInsensitiveDict:
        """Encrypt the data.

        :param data: A serialized block of byte data (String, JSON, bit array,
            etc.) Make sure that whatever you send, your client knows how
            to understand it.
        :type data: str
        :param content_encoding: The content_encoding type to use to encrypt
            the data. Defaults to RFC8188 "aes128gcm". The previous draft-01 is
            "aesgcm", however this format is now deprecated.
        :type content_encoding: enum("aesgcm", "aes128gcm")

        """
        reply = CaseInsensitiveDict()
        # Salt is a random 16 byte array.
        if not data:
            self.verb("No data found...")
            raise NoData()
        if not self.auth_key or not self.receiver_key:
            raise WebPushException("No keys specified in subscription info")
        self.verb("Encoding data...")
        salt = None
        if content_encoding not in self.valid_encodings:
            raise WebPushException(
                "Invalid content encoding specified. "
                "Select from " + json.dumps(self.valid_encodings)
            )
        if content_encoding == "aesgcm":
            self.verb("Generating salt for aesgcm...")
            salt = os.urandom(16)
            logging.debug("Salt: {}".format(salt))
        # The server key is an ephemeral ECDH key used only for this
        # transaction
        server_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        crypto_key = server_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        if isinstance(data, six.text_type):
            data = bytes(data.encode("utf8"))
        if content_encoding == "aes128gcm":
            self.verb("Encrypting to aes128gcm...")
            encrypted = http_ece.encrypt(
                data,
                salt=salt,
                private_key=server_key,
                dh=self.receiver_key,
                auth_secret=self.auth_key,
                version=content_encoding,
            )
            reply["body"] = encrypted
        else:
            self.verb("Encrypting to aesgcm...")
            crypto_key = base64.urlsafe_b64encode(crypto_key).strip(b"=")
            encrypted = http_ece.encrypt(
                data,
                salt=salt,
                private_key=server_key,
                keyid=crypto_key.decode(),
                dh=self.receiver_key,
                auth_secret=self.auth_key,
                version=content_encoding,
            )
            reply["crypto_key"] = crypto_key
            reply["body"] = encrypted
            if salt:
                reply["salt"] = base64.urlsafe_b64encode(salt).strip(b"=")
        return reply

    def as_curl(self, endpoint: str, encoded_data: bytes, headers: Dict[str, str]):
        """Return the send as a curl command.

        Useful for debugging. This will write out the encoded data to a local
        file named `encrypted.data`

        :param endpoint: Push service endpoint URL
        :type endpoint: basestring
        :param encoded_data: byte array of encoded data
        :type encoded_data: bytearray
        :param headers: Additional headers for the send
        :type headers: dict
        :returns string

        """
        header_list = [
            '-H "{}: {}" \\ \n'.format(key.lower(), val) for key, val in headers.items()
        ]
        data = ""
        if encoded_data:
            with open("encrypted.data", "wb") as f:
                f.write(encoded_data)
            data = "--data-binary @encrypted.data"
        if "content-length" not in headers:
            self.verb("Generating content-length header...")
            header_list.append(
                '-H "content-length: {}" \\ \n'.format(len(encoded_data))
            )
        return """curl -vX POST {url} \\\n{headers}{data}""".format(
            url=endpoint, headers="".join(header_list), data=data
        )

    def _prepare_send_data(
        self,
        data: Union[None, bytes] = None,
        headers: Union[None, Dict[str, str]] = None,
        ttl: int = 0,
        gcm_key: Union[None, str] = None,
        reg_id: Union[None, str] = None,
        content_encoding: str = "aes128gcm",
        curl: bool = False,
    ) -> dict:
        """Encode and send the data to the Push Service.

        :param data: A serialized block of data (see encode() ).
        :type data: str
        :param headers: A dictionary containing any additional HTTP headers.
        :type headers: dict
        :param ttl: The Time To Live in seconds for this message if the
            recipient is not online. (Defaults to "0", which discards the
            message immediately if the recipient is unavailable.)
        :type ttl: int
        :param gcm_key: API key obtained from the Google Developer Console.
            Needed if endpoint is https://android.googleapis.com/gcm/send
        :type gcm_key: string
        :param reg_id: registration id of the recipient. If not provided,
            it will be extracted from the endpoint.
        :type reg_id: str
        :param content_encoding: ECE content encoding (defaults to "aes128gcm")
        :type content_encoding: str
        :param curl: Display output as `curl` command instead of sending
        :type curl: bool
        """
        # Encode the data.
        if headers is None:
            headers = dict()
        encoded = CaseInsensitiveDict()
        headers = CaseInsensitiveDict(headers)
        if data:
            encoded = self.encode(data, content_encoding)
            if "crypto_key" in encoded:
                # Append the p256dh to the end of any existing crypto-key
                crypto_key = headers.get("crypto-key", "")
                if crypto_key:
                    # due to some confusion by a push service provider, we
                    # should use ';' instead of ',' to append the headers.
                    # see
                    # https://github.com/webpush-wg/webpush-encryption/issues/6
                    crypto_key += ";"
                crypto_key += "dh=" + encoded["crypto_key"].decode("utf8")
                headers.update({"crypto-key": crypto_key})
            if "salt" in encoded:
                headers.update({"encryption": "salt=" + encoded["salt"].decode("utf8")})
            headers.update(
                {
                    "content-encoding": content_encoding,
                }
            )
        if gcm_key:
            # guess if it is a legacy GCM project key or actual FCM key
            # gcm keys are all about 40 chars (use 100 for confidence),
            # fcm keys are 153-175 chars
            if len(gcm_key) < 100:
                self.verb("Guessing this is legacy GCM...")
                endpoint = "https://android.googleapis.com/gcm/send"
            else:
                self.verb("Guessing this is FCM...")
                endpoint = "https://fcm.googleapis.com/fcm/send"
            reg_ids = []
            if not reg_id:
                reg_id = cast(str, self.subscription_info["endpoint"]).rsplit("/", 1)[
                    -1
                ]
                self.verb("Fetching out registration id: {}", reg_id)
            reg_ids.append(reg_id)
            gcm_data = dict()
            gcm_data["registration_ids"] = reg_ids
            if data:
                buffer = encoded.get("body")
                if buffer:
                    gcm_data["raw_data"] = base64.b64encode(buffer).decode("utf8")
            gcm_data["time_to_live"] = int(headers["ttl"] if "ttl" in headers else ttl)
            encoded_data = json.dumps(gcm_data)
            headers.update(
                {
                    "Authorization": "key=" + gcm_key,
                    "Content-Type": "application/json",
                }
            )
        else:
            encoded_data = encoded.get("body")
            endpoint = self.subscription_info["endpoint"]

        if "ttl" not in headers or ttl:
            self.verb("Generating TTL of 0...")
            headers["ttl"] = str(ttl or 0)
        # Additionally useful headers:
        # Authorization / Crypto-Key (VAPID headers)

        self.verb(
            "\nSending request to" "\n\thost: {}\n\theaders: {}\n\tdata: {}",
            endpoint,
            headers,
            encoded_data,
        )

        return {"endpoint": endpoint, "data": encoded_data, "headers": headers}

    def send(self, *args, **kwargs) -> Union[Response, str]:
        """Encode and send the data to the Push Service"""
        timeout = kwargs.pop("timeout", 10000)
        curl = kwargs.pop("curl", False)

        params = self._prepare_send_data(*args, **kwargs)
        endpoint = params.pop("endpoint")

        if curl:
            encoded_data = params["data"]
            headers = params["headers"]
            return self.as_curl(endpoint, encoded_data=encoded_data, headers=headers)

        resp = self.requests_method.post(
            endpoint,
            timeout=timeout,
            **params,
        )
        self.verb(
            "\nResponse:\n\tcode: {}\n\tbody: {}\n",
            resp.status_code,
            resp.text or "Empty",
        )
        return resp

    async def send_async(self, *args, **kwargs) -> Union[aiohttp.ClientResponse, str]:
        timeout = kwargs.pop("timeout", 10000)
        curl = kwargs.pop("curl", False)

        params = self._prepare_send_data(*args, **kwargs)
        endpoint = params.pop("endpoint")

        if curl:
            encoded_data = params["data"]
            headers = params["headers"]
            return self.as_curl(endpoint, encoded_data=encoded_data, headers=headers)
        if self.aiohttp_session:
            resp = await self.aiohttp_session.post(endpoint, timeout=timeout, **params)
            resp_text = await resp.text()
        else:
            async with aiohttp.ClientSession() as session:
                resp = await session.post(endpoint, timeout=timeout, **params)
                resp_text = await resp.text()
        self.verb(
            "\nResponse:\n\tcode: {}\n\tbody: {}\n",
            resp.status,
            resp_text or "Empty",
        )
        return resp


def webpush(
    subscription_info: Dict[
        str, Union[Union[str, bytes], Dict[str, Union[str, bytes]]]
    ],
    data: Union[None, str] = None,
    vapid_private_key: Union[None, Vapid, str] = None,
    vapid_claims: Union[None, Dict[str, Union[str, int]]] = None,
    content_encoding: str = "aes128gcm",
    curl: bool = False,
    timeout: Union[None, float] = None,
    ttl: int = 0,
    verbose: bool = False,
    headers: Union[None, Dict[str, Union[str, int, float]]] = None,
    requests_session: Union[None, requests.Session] = None,
) -> Union[str, requests.Response]:
    """
        One call solution to endcode and send `data` to the endpoint
        contained in `subscription_info` using optional VAPID auth headers.

        in example:

        .. code-block:: python

        from pywebpush import python

        webpush(
            subscription_info={
                "endpoint": "https://push.example.com/v1/abcd",
                "keys": {"p256dh": "0123abcd...",
                         "auth": "001122..."}
                 },
            data="Mary had a little lamb, with a nice mint jelly",
            vapid_private_key="path/to/key.pem",
            vapid_claims={"sub": "YourNameHere@example.com"}
            )

        No additional method call is required. Any non-success will throw a
        `WebPushException`.

    :param subscription_info: Provided by the client call
    :type subscription_info: dict
    :param data: Serialized data to send
    :type data: str
    :param vapid_private_key: Vapid instance or path to vapid private key PEM \
                              or encoded str
    :type vapid_private_key: Union[Vapid, str]
    :param vapid_claims: Dictionary of claims ('sub' required)
    :type vapid_claims: dict
    :param content_encoding: Optional content type string
    :type content_encoding: str
    :param curl: Return as "curl" string instead of sending
    :type curl: bool
    :param timeout: POST requests timeout
    :type timeout: float
    :param ttl: Time To Live
    :type ttl: int
    :param verbose: Provide verbose feedback
    :type verbose: bool
    :return requests.Response or string
    :param headers: Dictionary of extra HTTP headers to include
    :type headers: dict

    """
    if headers is None:
        headers = dict()
    else:
        # Ensure we don't leak VAPID headers by mutating the passed in dict.
        headers = headers.copy()

    vapid_headers = None
    if vapid_claims:
        if verbose:
            logging.info("Generating VAPID headers...")
        if not vapid_claims.get("aud"):
            url = urlparse(cast(str, subscription_info.get("endpoint")))
            aud = "{}://{}".format(url.scheme, url.netloc)
            vapid_claims["aud"] = aud
        # Remember, passed structures are mutable in python.
        # It's possible that a previously set `exp` field is no longer valid.
        if not vapid_claims.get("exp") or int(vapid_claims.get("exp") or 0) < int(
            time.time()
        ):
            # encryption lives for 12 hours
            vapid_claims["exp"] = int(time.time()) + (12 * 60 * 60)
            if verbose:
                logging.info("Setting VAPID expry to {}...".format(vapid_claims["exp"]))
        if not vapid_private_key:
            raise WebPushException("VAPID dict missing 'private_key'")
        if isinstance(vapid_private_key, Vapid01):
            if verbose:
                logging.info("Looks like we already have a valid VAPID key")
            vv = vapid_private_key
        elif os.path.isfile(vapid_private_key):
            # Presume that key from file is handled correctly by
            # py_vapid.
            if verbose:
                logging.info("Reading VAPID key from file {}".format(vapid_private_key))
            vv = Vapid.from_file(private_key_file=vapid_private_key)  # pragma no cover
        else:
            if verbose:
                logging.info("Reading VAPID key from arguments")
            vv = Vapid.from_string(private_key=vapid_private_key)
        if verbose:
            logging.info("\t claims: {}".format(vapid_claims))
        vapid_headers = vv.sign(vapid_claims)
        if verbose:
            logging.info("\t headers: {}".format(vapid_headers))
        headers.update(vapid_headers)

    response = WebPusher(
        subscription_info, requests_session=requests_session, verbose=verbose
    ).send(
        data,
        headers,
        ttl=ttl,
        content_encoding=content_encoding,
        curl=curl,
        timeout=timeout,
    )
    if not curl and cast(Response, response).status_code > 202:
        response = cast(Response, response)
        raise WebPushException(
            "Push failed: {} {}\nResponse body:{}".format(
                response.status_code, response.reason, response.text
            ),
            response=response,
        )
    return response


async def webpush_async(
    subscription_info: Dict[
        str, Union[Union[str, bytes], Dict[str, Union[str, bytes]]]
    ],
    data: Union[None, str] = None,
    vapid_private_key: Union[None, Vapid, str] = None,
    vapid_claims: Union[None, Dict[str, Union[str, int]]] = None,
    content_encoding: str = "aes128gcm",
    curl: bool = False,
    timeout: Union[None, float] = None,
    ttl: int = 0,
    verbose: bool = False,
    headers: Union[None, Dict[str, Union[str, int, float]]] = None,
    aiohttp_session: Union[None, aiohttp.ClientSession] = None,
) -> Union[str, aiohttp.ClientResponse]:
    """
        Async version of webpush function. One call solution to encode and send 
        `data` to the endpoint contained in `subscription_info` using optional 
        VAPID auth headers.

        Example:

        .. code-block:: python

        from pywebpush import webpush_async
        import asyncio

        async def send_notification():
            response = await webpush_async(
                subscription_info={
                    "endpoint": "https://push.example.com/v1/abcd",
                    "keys": {"p256dh": "0123abcd...",
                             "auth": "001122..."}
                     },
                data="Mary had a little lamb, with a nice mint jelly",
                vapid_private_key="path/to/key.pem",
                vapid_claims={"sub": "YourNameHere@example.com"}
                )

        asyncio.run(send_notification())

        No additional method call is required. Any non-success will throw a
        `WebPushException`.

    :param subscription_info: Provided by the client call
    :type subscription_info: dict
    :param data: Serialized data to send
    :type data: str
    :param vapid_private_key: Vapid instance or path to vapid private key PEM \
                              or encoded str
    :type vapid_private_key: Union[Vapid, str]
    :param vapid_claims: Dictionary of claims ('sub' required)
    :type vapid_claims: dict
    :param content_encoding: Optional content type string
    :type content_encoding: str
    :param curl: Return as "curl" string instead of sending
    :type curl: bool
    :param timeout: POST requests timeout
    :type timeout: float
    :param ttl: Time To Live
    :type ttl: int
    :param verbose: Provide verbose feedback
    :type verbose: bool
    :param headers: Dictionary of extra HTTP headers to include
    :type headers: dict
    :param aiohttp_session: Optional aiohttp ClientSession for connection reuse
    :type aiohttp_session: aiohttp.ClientSession
    :return aiohttp.ClientResponse or string

    """
    if headers is None:
        headers = dict()
    else:
        # Ensure we don't leak VAPID headers by mutating the passed in dict.
        headers = headers.copy()

    vapid_headers = None
    if vapid_claims:
        if verbose:
            logging.info("Generating VAPID headers...")
        if not vapid_claims.get("aud"):
            url = urlparse(cast(str, subscription_info.get("endpoint")))
            aud = "{}://{}".format(url.scheme, url.netloc)
            vapid_claims["aud"] = aud
        # Remember, passed structures are mutable in python.
        # It's possible that a previously set `exp` field is no longer valid.
        if not vapid_claims.get("exp") or int(vapid_claims.get("exp") or 0) < int(
            time.time()
        ):
            # encryption lives for 12 hours
            vapid_claims["exp"] = int(time.time()) + (12 * 60 * 60)
            if verbose:
                logging.info(
                    "Setting VAPID expiry to {}...".format(vapid_claims["exp"])
                )
        if not vapid_private_key:
            raise WebPushException("VAPID dict missing 'private_key'")
        if isinstance(vapid_private_key, Vapid01):
            if verbose:
                logging.info("Looks like we already have a valid VAPID key")
            vv = vapid_private_key
        elif os.path.isfile(vapid_private_key):
            # Presume that key from file is handled correctly by
            # py_vapid.
            if verbose:
                logging.info("Reading VAPID key from file {}".format(vapid_private_key))
            vv = Vapid.from_file(private_key_file=vapid_private_key)  # pragma no cover
        else:
            if verbose:
                logging.info("Reading VAPID key from arguments")
            vv = Vapid.from_string(private_key=vapid_private_key)
        if verbose:
            logging.info("\t claims: {}".format(vapid_claims))
        vapid_headers = vv.sign(vapid_claims)
        if verbose:
            logging.info("\t headers: {}".format(vapid_headers))
        headers.update(vapid_headers)

    response = await WebPusher(
        subscription_info, aiohttp_session=aiohttp_session, verbose=verbose
    ).send_async(
        data,
        headers,
        ttl=ttl,
        content_encoding=content_encoding,
        curl=curl,
        timeout=timeout,
    )
    if not curl and cast(aiohttp.ClientResponse, response).status > 202:
        response = cast(aiohttp.ClientResponse, response)
        response_text = await response.text()
        raise WebPushException(
            "Push failed: {} {}\nResponse body:{}".format(
                response.status, response.reason, response_text
            ),
            response=response,
        )
    return response
