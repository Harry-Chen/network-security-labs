cat as4538_prefix4.txt | parallel -j 24 sudo nmap -T5 -n -Pn -sn --script=./dns-query.nse -oN data/public_ns_server/\`date +%s%N\` {}
