[![Build_Status](https://travis-ci.org/jrconlin/pywebpush.svg?branch=master)](https://travis-ci.org/jrconlin/pywebpush)

# Webpush Data encryption library for Python

This is a work in progress.

## Installation

You'll need to run `python virtualenv`.
Then
```
bin/pip install -r requirements.txt
bin/python setup.py develop
```

## Usage

In the browser, the promise handler for
[registration.pushManager.subscribe()](https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe)
returns a
[PushSubscription](https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription)
object. This object has a .toJSON() method that will return a JSON
object that contains all the info we need to encrypt and push data.

As illustration, a subscription info object may look like:
```
{"endpoint": "https://updates.push.services.mozilla.com/push/v1/gAA...", "keys": {"auth": "k8J...", "p256dh": "BOr..."}}
```

How you send the PushSubscription data to your backend, store it
referenced to the user who requested it, and recall it when there's
new a new push subscription update is left as an excerise for the
reader.

The data can be any serial content (string, bit array, serialized
JSON, etc), but be sure that your receiving application is able to
parse and understand it. (e.g. `data = "Mary had a little lamb."`)

`headers` is a `dict`ionary of additional HTTP header values (e.g.
[VAPID](https://github.com/mozilla-services/vapid/tree/master/python)
self identification headers). It is optional and may be omitted.

to send:
```
WebPusher(subscription_info).send(data, headers)
```
You can also simply encode the data to send later by calling

```
encoded = WebPush(subscription_info).encode(data)
```
