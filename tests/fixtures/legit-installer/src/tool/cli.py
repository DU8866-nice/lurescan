
import argparse
from .resolver import step_1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="exampletool")
    ap.add_argument("packages", nargs="*")
    args = ap.parse_args(argv)
    print(step_1([{"name": p} for p in args.packages]))
    return 0
