import os
import subprocess
from subprocess import run, STDOUT, PIPE
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument('binary_path', type=str, help='path to assigner binary')
parser.add_argument('ll_file', type=str, help=' .ll file for assigner')
parser.add_argument('inp_file', type=str, help=' .inp file for assigner')
parser.add_argument('expected_tbl', type=str, help=' name of expected result file (.tbl)')
parser.add_argument('expected_crct', type=str, help=' name of expected result (.crct)')
parser.add_argument('real_tbl', type=str, help=' name of output (.tbl)')
parser.add_argument('real_crct', type=str, help=' name of output (.crct)')

args = parser.parse_args()
assigner_binary_path = args.binary_path
ll_file = args.ll_file
inp_file = args.inp_file
expected_tbl =  args.expected_tbl
expected_crct = args.expected_crct
real_tbl =  args.real_tbl
real_crct = args.real_crct

assigner_command = assigner_binary_path + " -b " + ll_file + " -i " + inp_file + " -t " + real_tbl + " -c " + real_crct + " -e pallas"

result = subprocess.run(assigner_command, shell=True)
if result.returncode != 0:
    sys.exit(ll_file + ": assignment failed!")

def print_green(a):
    print("\033[32m{}\033[0m".format(a))

def print_red(a):
    print("\033[31m{}\033[0m".format(a))

def compare(expected, real, test_type):
    res = subprocess.run(["diff", expected, real], stdout=PIPE, stderr=PIPE, text=True)
    print(ll_file + test_type + "comparison test: ", end = "")
    if res.returncode == 0:
        print_green("success!")
        # return 0
    if res.returncode == 2:
        print_red("failed!\n")
        # return 2
        # sys.exit(res.stderr)
    if res.returncode == 1:
        print_red("failed!\n")
        # return 1
        # sys.exit(f"{test_type} are not equal!\n{res.stdout}")
    return res


tbl_res = compare(expected_tbl, real_tbl, " assignment tables ")
crct_res = compare(expected_crct, real_crct, " circuit files ")

if (tbl_res.returncode != 0 or crct_res.returncode != 0):
    message = ""
    if (tbl_res.returncode == 2):
        message += tbl_res.stderr
        message += "\n"
    if (crct_res.returncode == 2):
        message += crct_res.stderr
        message += "\n"
    if (tbl_res.returncode == 1):
        message += f"assignment tables are not equal!\n{tbl_res.stdout}"
        message += "\n"
    if (crct_res.returncode == 1):
        message += f"circuit files are not equal!\n{crct_res.stdout}"
        message += "\n"
    sys.exit(message)
