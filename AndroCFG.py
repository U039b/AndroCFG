#!/usr/bin/env python3
import argparse

from androcfg.call_graph_extractor import CFG


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", help="APK to be analyzed", type=str, required=True)
    parser.add_argument("-o", "--output", help="Output directory", type=str, required=True)
    parser.add_argument("-r", "--rules", help="JSON file containing rules", type=str, required=False)
    parser.add_argument("-f", "--file", help="Sets the output file type for the code extraction (bmp, html, raw). Default is bmp", type=str, choices=['bmp', 'html', 'raw'], required=False)
    args = parser.parse_args()

    if args.rules:
        c = CFG(args.apk, args.output, args.rules. args.file)
    else:
        c = CFG(args.apk, args.output, args.file)
    c.compute_rules()
    c.generate_md_report()


if __name__ == '__main__':
    main()
