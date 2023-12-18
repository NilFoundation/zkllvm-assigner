import os
import subprocess

import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument('assigner_binary_path', type=str, help='path to assigner binary file')
args = parser.parse_args()
assigner_binary_path = args.assigner_binary_path

dirs = os.listdir("data/")

if not os.path.exists("real_res"):
    os.makedirs("real_res")

ll_names = []

tests_succeeded = True

for i in range(len(dirs)):
    if dirs[i].find(".ll") != -1:
        ll_names.append(dirs[i][:-3])

for i in range(len(ll_names)):
    for j in range(4):
        test_name = "data/" + ll_names[i] + "_" + str(j)
        if os.path.exists(test_name + ".inp") == True:
            res = subprocess.run(["python3", "test_script.py", assigner_binary_path, "data/" + ll_names[i]+".ll", test_name+".inp", test_name+".tbl", test_name+".crct", "real_res/" + test_name[5:]+".tbl", "real_res/" + test_name[5:]+".crct"])
            if (res.returncode != 0):
                tests_succeeded = False

res = subprocess.run(["rm", "-r", "real_res/"])

if (tests_succeeded != True):
    sys.exit("some tests failed")