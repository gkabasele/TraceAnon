import os
import argparse
from subprocess import call

parser = argparse.ArgumentParser()
parser.add_argument("--indir", type=str, dest="indir", action="store", help="directory to read")

args = parser.parse_args()

LEN_SUFF = len(".pcaped_filter.pcap")

for filename in os.listdir(args.indir):
    inname  = "/".join([args.indir, filename])
    new_name = inname[:-LEN_SUFF] + "_trunc.pcap"
    os.rename(inname, new_name)

