#!/usr/bin/env python3
from androcfg.call_graph_extractor import CFG
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", help="APK to be analyzed", type=str, required=True)
    parser.add_argument("-o", "--output", help="Output directory", type=str, required=True)
    parser.add_argument("-r", "--rules", help="JSON file containing rules", type=str, required=False)
    args = parser.parse_args()

    if args.rules:
        c = CFG(args.apk, args.output, args.rules)
    else:
        c = CFG(args.apk, args.output)
    c.compute_rules()
    c.generate_md_report()


if __name__ == '__main__':
    main()
