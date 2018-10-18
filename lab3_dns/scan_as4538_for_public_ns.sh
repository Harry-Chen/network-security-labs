mkdir -p data/public_ns/
cat data/as4538_prefix4.txt | parallel -j 24 sudo nmap -T5 -n -Pn -sn --script=./test_dns_query.nse -oN data/public_ns/\`date +%s%N\` {}
