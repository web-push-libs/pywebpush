|Build\_Status| [|Requirements Status|]

Webpush Data encryption library for Python
==========================================

This is a work in progress. This library is available on `pypi as
pywebpush <https://pypi.python.org/pypi/pywebpush>`__. Source is
available on `github <https://github.com/web-push-libs/pywebpush>`__

Installation
------------

You'll need to run ``python virtualenv``. Then

::

    bin/pip install -r requirements.txt
    bin/python setup.py develop

Usage
-----

In the browser, the promise handler for
`registration.pushManager.subscribe() <https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe>`__
returns a
`PushSubscription <https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription>`__
object. This object has a .toJSON() method that will return a JSON
object that contains all the info we need to encrypt and push data.

As illustration, a subscription info object may look like:

::

    {"endpoint": "https://updates.push.services.mozilla.com/push/v1/gAA...", "keys": {"auth": "k8J...", "p256dh": "BOr..."}}

How you send the PushSubscription data to your backend, store it
referenced to the user who requested it, and recall it when there's new
a new push subscription update is left as an excerise for the reader.

The data can be any serial content (string, bit array, serialized JSON,
etc), but be sure that your receiving application is able to parse and
understand it. (e.g. ``data = "Mary had a little lamb."``)

gcm\_key is the API key obtained from the Google Developer Console. It
is only needed if endpoint is https://android.googleapis.com/gcm/send

``headers`` is a ``dict``\ ionary of additional HTTP header values (e.g.
`VAPID <https://github.com/mozilla-services/vapid/tree/master/python>`__
self identification headers). It is optional and may be omitted.

to send:

::

    WebPusher(subscription_info).send(data, headers)

to send for Chrome:

::

    WebPusher(subscription_info).send(data, headers, ttl, gcm_key)

You can also simply encode the data to send later by calling

::

    encoded = WebPush(subscription_info).encode(data)

.. |Build\_Status| image:: https://travis-ci.org/web-push-libs/pywebpush.svg?branch=master
   :target: https://travis-ci.org/web-push-libs/pywebpush
.. |Requirements Status| image:: https://requires.io/github/web-push-libs/pywebpush/requirements.svg?branch=master
