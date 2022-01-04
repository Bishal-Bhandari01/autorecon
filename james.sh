#!/bin/bash

if [ -z "$1" ]
then
        echo "Usage: ./james.sh <domain>"
        echo "Example: ./james.sh yahoo.com"
        exit 1
fi

#edit directory before starting the bash script
cd ..
mkdir $1 #$1 stands for domain given to enum
cd $1

#saved directories(don't edit this.)
if [ ! -d "thirdlevel" ]; then
	mkdir thirdlevels
fi

if [ ! -d "scans" ]; then
	mkdir scans
fi

printf "\n\n =====================================> Stating Recon <===================================== \n\n"

echo "=====================================> Gathering subdomains with subliat3r... <====================================="
sublist3r -d $1 -o results.txt #if you have subfinder then change sublist3r with subfinder.

echo $1 >> results.txt

echo "=====================================> Gathering third-level domains... <====================================="
cat results.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> third-level.txt #it will gather subdomain like about.example.com and sort the list of domain.

echo "=====================================> Gathering thirdlevel domains with sublist3r... <====================================="
for domain in $(cat third-level.txt); do
	sublist3r -d $domain -o thirdlevels/$domain.txt; #it will check the subdomain and scan 3rd domain like dev.about.example.com and save it on the given file. 
	cat thirdlevels/$domain.txt | sort -u >> results.txt; #it will show and sort the domain list. 
done

echo "=====================================> Probing subdomains with httprobe... <====================================="
cat results.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' |tr -d ":443" > probed.txt
#it will check, sort, port checking, remove the https and save it on the given file. 

echo "=====================================> Scanning for open ports... <====================================="
nmap -iL probed.txt -oA scans/scanned.txt
#it will scan list of domain one at a time nd shows which ports are open, closed and filtered. 

echo "=====================================> Running Aquatone... <====================================="
cat scans/scanned.txt | aquatone
#it will go to the domain and list the header, source and take the screenshot of the domain credentials. 

echo "=====================================> Starting Nuclei... <====================================="
#it will check the vulnerabilty like cves,CSRF-token and so on.
mkdir nuclei_op
nuclei -l probed.txt -t "/root/tools/nuclei-templates/cves/*.yaml" -c 60 -o nuclei_op/cves.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/files/*.yaml" -c 60 -o nuclei_op/files.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/panels/*.yaml" -c 60 -o nuclei_op/panels.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/security-misconfiguration/*.yaml" -c 60 -o nuclei_op/security-misconfiguration.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/technologies/*.yaml" -c 60 -o nuclei_op/technologies.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/tokens/*.yaml" -c 60 -o nuclei_op/tokens.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/vulnerabilities/*.yaml" -c 60 -o nuclei_op/vulnerabilities.txt

echo "=====================================> Now looking for CORS misconfiguration... <====================================="
python3 ~/tools/corsy.py -i probed.txt -t 40 | tee -a corsy_op.txt

echo "=====================================> Starting CMS detection... <====================================="
whatweb -i probed.txt | tee -a whatweb_op.txt

echo "=====================================> Running smuggler... <====================================="
#it will check the header and check if it will smuggle the sub-domain takerover.
python3 /home/meliodas/smuggler/smuggler.py -u probed.txt | tee -a smuggler_op.txt

printf "\n\n =====================================> Recon Stopped <====================================="
