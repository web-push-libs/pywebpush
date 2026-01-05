Webpush Data encryption library for Python
==========================================

This library is available on `pypi as
pywebpush <https://pypi.python.org/pypi/pywebpush>`__. Source is
available on `github <https://github.com/mozilla-services/pywebpush>`__.
Please note: This library was designated as a ``Critical Project`` by
PyPi, it is currently maintained by `a single
person <https://xkcd.com/2347/>`__. I still accept PRs and Issues, but
make of that what you will.

Installation
------------

To work with this repo locally, you’ll need to run
``python -m venv venv``. Then ``venv/bin/pip install --editable .``

Usage
-----

In the browser, the promise handler for
`registration.pushManager.subscribe() <https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe>`__
returns a
`PushSubscription <https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription>`__
object. This object has a .toJSON() method that will return a JSON
object that contains all the info we need to encrypt and push data.

As illustration, a ``subscription_info`` object may look like:

.. code:: json

   {
     "endpoint": "https://updates.push.services.mozilla.com/push/v1/gAA...",
     "keys": { "auth": "k8J...", "p256dh": "BOr..." }
   }

How you send the PushSubscription data to your backend, store it
referenced to the user who requested it, and recall it when there’s a
new push subscription update is left as an exercise for the reader.

*Note:* Some platforms (like Microsoft Windows) require additional
headers specified for the Push call. These additional headers are not
standard and may be rejected by other Push services. Please see `Special
Instructions <#special-instructions>`__ below.

Sending Data using ``webpush()`` One Call
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In many cases, your code will be sending a single message to many
recipients. There’s a “One Call” function which will make things easier.

.. code:: python

   from pywebpush import webpush

   webpush(subscription_info,
           data,
           vapid_private_key="Private Key or File Path[1]",
           vapid_claims={"sub": "mailto:YourEmailAddress"})

This will encode ``data``, add the appropriate VAPID auth headers if
required and send it to the push server identified in the
``subscription_info`` block.

Parameters
^^^^^^^^^^

*subscription_info* - The ``dict`` of the subscription info (described
above).

*data* - can be any serial content (string, bit array, serialized JSON,
etc), but be sure that your receiving application is able to parse and
understand it. (e.g. ``data = "Mary had a little lamb."``)

*content_type* - specifies the form of Encryption to use, either
``'aes128gcm'`` or the deprecated ``'aesgcm'``. NOTE that not all User
Agents can decrypt ``'aesgcm'``, so the library defaults to the RFC 8188
standard form.

*vapid_claims* - a ``dict`` containing the VAPID claims required for
authorization (See
`py_vapid <https://github.com/web-push-libs/vapid/tree/master/python>`__
for more details). If ``aud`` is not specified, pywebpush will attempt
to auto-fill from the ``endpoint``. If ``exp`` is not specified or set
in the past, it will be set to 12 hours from now. In both cases, the
passed ``dict`` **will be mutated** after the call.

*vapid_private_key* - Either a path to a VAPID EC2 private key PEM file,
or a string containing the DER representation. (See
`py_vapid <https://github.com/web-push-libs/vapid/tree/master/python>`__
for more details.) The ``private_key`` may be a base64 encoded DER
formatted private key, or the path to an OpenSSL exported private key
file.

e.g. the output of:

.. code:: bash

   openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem

Example
^^^^^^^

.. code:: python

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
                   "sub": "mailto:YourNameHere@example.org",
               }
       )
   except WebPushException as ex:
       print("I'm sorry, Dave, but I can't do that: {}", repr(ex))
       # Mozilla returns additional information in the body of the response.
       if ex.response is not None and ex.response.json():
           extra = ex.response.json()
           print("Remote service replied with a {}:{}, {}",
                 extra.code,
                 extra.errno,
                 extra.message
                 )

Methods
~~~~~~~

If you expect to resend to the same recipient, or have more needs than
just sending data quickly, you can pass just
``wp = WebPusher(subscription_info)``. This will return a ``WebPusher``
object.

The following methods are available:

``.send(data, headers={}, ttl=0, reg_id="", content_encoding="aes128gcm", curl=False, timeout=None)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Send the data using additional parameters. On error, returns a
``WebPushException``

.. _parameters-1:

Parameters
''''''''''

*data* Binary string of data to send

*headers* A ``dict`` containing any additional headers to send

*ttl* Message Time To Live on Push Server waiting for the client to
reconnect (in seconds)

*reg_id* Google Cloud Messaging registration ID (will be extracted from
endpoint if not specified)

*content_encoding* ECE content encoding type (defaults to “aes128gcm”)

*curl* Do not execute the POST, but return as a ``curl`` command. This
will write the encrypted content to a local file named
``encrpypted.data``. This command is meant to be used for debugging
purposes.

*timeout* timeout for requests POST query. See `requests
documentation <http://docs.python-requests.org/en/master/user/quickstart/#timeouts>`__.

.. _example-1:

Example
'''''''

to send to a user on Chrome:

.. code:: python

   WebPusher(subscription_info).send(data, headers, ttl)

``.encode(data, content_encoding="aes128gcm")``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Encode the ``data`` for future use. On error, returns a
``WebPushException``

.. _parameters-2:

Parameters
''''''''''

*data* Binary string of data to send

*content_encoding* ECE content encoding type (defaults to “aes128gcm”)

*Note* This will return a ``NoData`` exception if the data is not
present or empty. It is completely valid to send a WebPush notification
with no data, but encoding is a no-op in that case. Best not to call it
if you don’t have data.

.. _example-2:

Example
'''''''

.. code:: python

   encoded_data = WebPush(subscription_info).encode(data)

Stand Alone Webpush
-------------------

If you’re not really into coding your own solution, there’s also a
“stand-alone” ``pywebpush`` command in the ``./bin`` directory.

This uses two files:

-  the *data* file, which contains the message to send, in whatever form
   you like.
-  the *subscription info* file, which contains the subscription
   information as JSON encoded data. This is usually returned by the
   Push ``subscribe`` method and looks something like:

.. code:: json

   {
     "endpoint": "https://push...",
     "keys": {
       "auth": "ab01...",
       "p256dh": "aa02..."
     }
   }

If you’re interested in just testing your applications WebPush
interface, you could use the Command Line:

.. code:: bash

   ./bin/pywebpush --data stuff_to_send.data --info subscription.info

which will encrypt and send the contents of ``stuff_to_send.data``.

See ``./bin/pywebpush --help`` for available commands and options.

Special Instructions
--------------------

Windows
~~~~~~~

`Microsoft
requires <https://learn.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/push-request-response-headers#request-parameters>`__
one extra header and suggests several additional headers. Users have
reported that not including these headers can cause notifications to
fail to appear. These additional headers are non-standard and may be
rejected by other platforms. You should be cautious including them with
calls to non-Microsoft platforms, or to non-Microsoft destinations.

As of 2024-Apr-19, Microsoft requires an ``X-WNS-Type`` header. As an
example, you can include this header within the command line call:

Content of the ``windows_headers.json`` file:

.. code:: json

   {"X-WNS-Type":"wns/toast", "TTL":600, "Content-Type": "text/xml"}

*Note* : This includes both the ``TTL`` set to 10 minutes and the
required matching ``Content-Type`` header for ``wns/toast``.

.. code:: bash

   pywebpush --data stuff_to_send.xml \
      --info edge_user_info.json \
      --head windows_headers.json \
      --claims vapid_claims.json

Google Cloud Messaging (GCM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please note that GCM has been sunset by Google. Providers should use
`Firebase Cloud
Messaging <https://firebase.google.com/support/troubleshooter/fcm/tokens/gcm>`__
instead.

Please also note that sending messages directly to FCM is not supported
by this library. In the past, you could use an insecure ``gcm_key`` as a
proxy for the authentication service. `This was disabled in June
2024 <https://firebase.google.com/docs/cloud-messaging/auth-server#authorize-legacy-protocol-send-requests>`__.

Sending WebPush messages to Google Chrome users should not be impacted
by this change.
