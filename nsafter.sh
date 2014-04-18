#!/usr/bin/bash

# Download the script that generates the Netscaler's config
curl --insecure -o /nsconfig/nsconfig.sh https://raw.github.com/willjasen/netscaler-bootstrap/nsconfig.sh

# Make the downloaded script executable
chmod +x /nsconfig/nsconfig.sh

# Run the script to generate the Netscaler's configuration
/usr/bin/bash /nsconfig/nsconfig.sh \
	/nsconfig/ns.conf \					# Path of Netscaler's configuration
	DOMAIN \							# Domain name
	DOMAINPASSWORD \					# Domain administrator password
	https://certificates.url \			# Certificates file URL
	PFXPASS								# Certificates password
	