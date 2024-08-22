# I am terrible at keeping this up-to-date.
## 2.1.0 (2024-04-19)
Add comment discussing additional work for Windows Notification Service (WNS)
* Update the README.md file to mention the required, non-standard headers.

*BREAKING_CHANGE*
This version also drops legacy support for GCM/FCM authorization keys, since those items
are obsolete according to Google.
See https://firebase.google.com/docs/cloud-messaging/auth-server#authorize-legacy-protocol-send-requests

## 2.0.0 (2024-01-02)
chore: Update to modern python practices
* include pyproject.toml file
* use python typing
* update to use pytest

 *BREAKING_CHANGE*
 `Webpusher.encode` will now return a `NoData` exception if no data is present to encode. Chances are
 you probably won't be impacted by this change since most push messages contain data, but one never knows.
 This alters the prior behavior where it would return `None`.

## 1.14.0 (2021-07-28)
bug: accept all VAPID key instances (thanks @mthu)

## 1.13.0 (2021-03-15)
Support requests_session param in webpush fn too (thanks @bwindels)

## 1.12.0 (2021-03-15)
chore: library update, remove nose tests

## 1.11.0 (2020-04-29)
feat: add `--head` to read headers out of a json file (thanks @braedon)

## 1.10.2 (2020-04-11)
bug: update min vapid requirement to 1.7.0

## 1.10.1 (2019-12-03)
feat: use six.text_type instead of six.string_types

## 1.10.0 (2019-08-13)
feat: Add `--verbose` flag with some initial commentary
bug: Update tests to use latest VAPID version

## 1.9.4 (2019-05-09)
bug: update vapid `exp` header if missing or expired

## 0.7.0 (2017-02-14)
feat: update to http-ece 0.7.0 (with draft-06 support)
feat: Allow empty payloads for send()
feat: Add python3 classfiers & python3.6 travis tests
feat: Add README.rst
bug: change long to int to support python3

## 0.4.0 (2016-06-05)
feat: make python 2.7 / 3.5 polyglot

## 0.3.4 (2016-05-17)
bug: make header keys case insenstive

## 0.3.3 (2016-05-17)
bug: force key string encoding to utf8

## 0.3.2 (2016-04-28)
bug: fix setup.py issues

## 0.3 (2016-04-27)
feat: added travis, normalized directories


## 0.2 (2016-04-27)
feat: Added tests, restructured code


## 0.1 (2016-04-25)

Initial release
