import argparse
import os
import json

from pywebpush import webpush


def get_config():
    parser = argparse.ArgumentParser(description="WebPush tool")
    parser.add_argument("--data", '-d', help="Data file")
    parser.add_argument("--info", "-i", help="Subscription Info JSON file")
    parser.add_argument("--head", help="Header Info JSON file")
    parser.add_argument("--claims", help="Vapid claim file")
    parser.add_argument("--key", help="Vapid private key file path")
    parser.add_argument("--curl", help="Don't send, display as curl command",
                        default=False, action="store_true")
    parser.add_argument("--encoding", default="aes128gcm")
    parser.add_argument("--verbose", "-v", help="Provide verbose feedback",
                        default=False, action="store_true")

    args = parser.parse_args()

    if not args.info:
        raise Exception("Subscription Info argument missing.")
    if not os.path.exists(args.info):
        raise Exception("Subscription Info file missing.")
    try:
        with open(args.info) as r:
            args.sub_info = json.loads(r.read())
        if args.data:
            with open(args.data) as r:
                args.data = r.read()
        if args.head:
            with open(args.head) as r:
                args.head = json.loads(r.read())
        if args.claims:
            if not args.key:
                raise Exception("No private --key specified for claims")
            with open(args.claims) as r:
                args.claims = json.loads(r.read())
    except Exception as ex:
        print("Couldn't read input {}.".format(ex))
        raise ex
    return args


def main():
    """ Send data """

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
            headers=args.head)
        print(result)
    except Exception as ex:
        print("ERROR: {}".format(ex))


if __name__ == "__main__":
    main()
