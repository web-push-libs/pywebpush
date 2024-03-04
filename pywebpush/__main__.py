import argparse
import os
import json
import logging

from requests import JSONDecodeError

from pywebpush import webpush, WebPushException


def get_config():
    parser = argparse.ArgumentParser(description="WebPush tool")
    parser.add_argument("--data", "-d", help="Data file")
    parser.add_argument("--info", "-i", help="Subscription Info JSON file")
    parser.add_argument("--head", help="Header Info JSON file")
    parser.add_argument("--claims", help="Vapid claim file")
    parser.add_argument("--key", help="Vapid private key file path")
    parser.add_argument(
        "--curl",
        help="Don't send, display as curl command",
        default=False,
        action="store_true",
    )
    parser.add_argument("--encoding", default="aes128gcm")
    parser.add_argument(
        "--verbose",
        "-v",
        help="Provide verbose feedback",
        default=False,
        action="store_true",
    )

    args = parser.parse_args()

    if not args.info:
        raise WebPushException("Subscription Info argument missing.")
    if not os.path.exists(args.info):
        raise WebPushException("Subscription Info file missing.")
    try:
        with open(args.info) as r:
            try:
                args.sub_info = json.loads(r.read())
            except JSONDecodeError as e:
                raise WebPushException(
                    "Could not read the subscription info file: {}", e
                )
        if args.data:
            with open(args.data) as r:
                args.data = r.read()
        if args.head:
            with open(args.head) as r:
                try:
                    args.head = json.loads(r.read())
                except JSONDecodeError as e:
                    raise WebPushException("Could not read the header arguments: {}", e)
        if args.claims:
            if not args.key:
                raise WebPushException("No private --key specified for claims")
            with open(args.claims) as r:
                try:
                    args.claims = json.loads(r.read())
                except JSONDecodeError as e:
                    raise WebPushException(
                        "Could not read the VAPID claims file {}".format(e)
                    )
    except Exception as ex:
        logging.error("Couldn't read input {}.".format(ex))
        raise ex
    return args


def main():
    """Send data"""

    try:
        args = get_config()
        result = webpush(
            args.sub_info,
            data=args.data,
            vapid_private_key=args.key,
            vapid_claims=args.claims,
            curl=args.curl,
            content_encoding=args.encoding,
            verbose=args.verbose,
            headers=args.head,
        )
        print(result)
    except Exception as ex:
        logging.error("{}".format(ex))


if __name__ == "__main__":
    main()
