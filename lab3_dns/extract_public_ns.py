#!/usr/bin/env python3
# coding: utf-8


import re
from pathlib import Path


def process_raw_result(s):
    correct_ip = []
    wrong_ip = []
    error_ip = []
    regex="""(\d+\.\d+\.\d+\.\d+)\nHost is up.\n\nHost script results:\n\|_dns-query: (.*?)\n"""
    for (ip, response) in re.findall(regex, s):
        if response == '166.111.4.79': # correct address
            correct_ip.append(ip)
        elif 'ERROR' in response:
            error_ip.append(ip)
        else:
            wrong_ip.append("{}:{}".format(ip, response))
    return correct_ip, wrong_ip, error_ip

	
data_dir = (Path() / 'data' / 'public_ns').resolve()
file_list = [str(x.resolve()) for x in data_dir.iterdir() if not x.is_dir()]

correct = []
wrong = []
error = []

for file in file_list:
    with open(file, 'r') as f:
        correct_ip, wrong_ip, error_ip = process_raw_result(f.read())
        correct.extend(correct_ip)
        wrong.extend(wrong_ip)
        error.extend(error_ip)
        print("File {} contains {} correct results, {} wrong results and {} error results".format(file, len(correct_ip), len(wrong_ip), len(error_ip)))


print("All results contains {} correct results, {} wrong results and {} error results".format(len(correct), len(wrong), len(error)))


with open('data/as4538_public_ns.txt', 'w') as f:
    f.write('\n'.join(correct) + '\n')
    
with open('data/as4538_public_ns_error.txt', 'w') as f:
    f.write('\n'.join(error) + '\n')
    
with open('data/as4538_public_ns_wrong.txt', 'w') as f:
    f.write('\n'.join(wrong) + '\n')



