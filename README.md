[![Build_Status](https://travis-ci.org/web-push-libs/pywebpush.svg?branch=master)](https://travis-ci.org/web-push-libs/pywebpush)
[![Requirements
Status](https://requires.io/github/web-push-libs/pywebpush/requirements.svg?branch=feat%2F44)](https://requires.io/github/web-push-libs/pywebpush/requirements/?branch=master)

# Webpush Data encryption library for Python

This is a work in progress.
This library is available on [pypi as pywebpush](https://pypi.python.org/pypi/pywebpush).
Source is available on
[github](https://github.com/mozilla-services/pywebpush).

## Installation

You'll need to run `python virtualenv`.
Then
```commandline
bin/pip install -r requirements.txt
bin/python setup.py develop
```

## Usage

In the browser, the promise handler for
[registration.pushManager.subscribe()](https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe)
returns a
[PushSubscription](https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription)
object. This object has a .toJSON() method that will return a JSON object that contains all the info we need to encrypt
and push data.

As illustration, a `subscription_info` object may look like:
```json
{"endpoint": "https://updates.push.services.mozilla.com/push/v1/gAA...", "keys": {"auth": "k8J...", "p256dh": "BOr..."}}
```

How you send the PushSubscription data to your backend, store it
referenced to the user who requested it, and recall it when there's
a new push subscription update is left as an exercise for the
reader.

### Sending Data using `webpush()` One Call

In many cases, your code will be sending a single message to many
recipients. There's a "One Call" function which will make things
easier.

```pythonstub
    from pywebpush import webpush

    webpush(subscription_info,
            data,
            vapid_private_key="Private Key or File Path[1]",
            vapid_claims={"sub": "mailto:YourEmailAddress"})
```
This will encode `data`, add the appropriate VAPID auth headers if required and send it to the push server identified
in the `subscription_info` block.

**Parameters**

*subscription_info* - The `dict` of the subscription info (described above).

*data* - can be any serial content (string, bit array, serialized JSON, etc), but be sure that your receiving
application is able to parse and understand it. (e.g. `data = "Mary had a little lamb."`)

*vapid_claims* - a `dict` containing the VAPID claims required for authorization (See
[py_vapid](https://github.com/web-push-libs/vapid/tree/master/python) for more details)

*vapid_private_key* - Either a path to a VAPID EC2 private key PEM file, or a string containing the DER representation.
(See [py_vapid](https://github.com/web-push-libs/vapid/tree/master/python) for more details.) The `private_key` may be
a base64 encoded DER formatted private key, or the path to an OpenSSL exported private key file.

e.g. the output of:
```commandline
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
```

**Example**

```pythonstub
from pywebpush import webpush, WebPushException

try:
    webpush(
        subscription_info={
            "endpoint": "https://push.example.com/v1/12345",
            "keys": {
                "p256dh": "0123abcde...",
                "auth": "abc123..."
            }},
        data="Mary had a little lamb, with a nice mint jelly",
        vapid_private_key="path/to/vapid_private.pem",
        vapid_claims={
                "sub": "YourNameHere@example.org",
            }
    )
except WebPushException as ex:
    print("I'm sorry, Dave, but I can't do that: {}", repr(ex))
```

### Methods

If you expect to resend to the same recipient, or have more needs than just sending data quickly, you
can pass just `wp = WebPusher(subscription_info)`. This will return a `WebPusher` object.

The following methods are available:

#### `.send(data, headers={}, ttl=0, gcm_key="", reg_id="", content_encoding="aesgcm", curl=False)`

Send the data using additional parameters. On error, returns a `WebPushException`

**Parameters**

*data* Binary string of data to send

*headers* A `dict` containing any additional headers to send

*ttl* Message Time To Live on Push Server waiting for the client to reconnect (in seconds)

*gcm_key* Google Cloud Messaging key (if using the older GCM push system) This is the API key obtained from the Google
Developer Console.

*reg_id* Google Cloud Messaging registration ID (will be extracted from endpoint if not specified)

*content_encoding* ECE content encoding type (defaults to "aesgcm")

*curl* Do not execute the POST, but return as a `curl` command. This will write the encrypted content to a local file
named `encrpypted.data`. This command is meant to be used for debugging purposes.

**Example**

to send from Chrome using the old GCM mode:
```pythonstub
WebPusher(subscription_info).send(data, headers, ttl, gcm_key)
```

#### `.encode(data, content_encoding="aesgcm")`

Encode the `data` for future use. On error, returns a `WebPushException`

**Parameters**

*data* Binary string of data to send

*content_encoding* ECE content encoding type (defaults to "aesgcm")

**Example**

```pythonstub
encoded_data = WebPush(subscription_info).encode(data)
```


