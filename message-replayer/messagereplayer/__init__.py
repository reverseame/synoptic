import sys

import messagereplayer.args
import messagereplayer.replayer as replayer

def main():
    args = messagereplayer.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        print("message-replayer: v0.0.1")
        sys.exit(0)

    replayer.Replayer(args.host, args.port, tcp=not args.udp).replay(args.model, delay=args.delay)
