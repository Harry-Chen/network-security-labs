mkdir -p public_ns/
cat ../as4538_addresses/as4538_prefix4.txt | parallel -j 24 sudo nmap -T5 -n -Pn -sn --script=./test_dns_query.nse -oN public_ns/\`date +%s%N\` {}
