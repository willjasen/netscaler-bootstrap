#!/usr/bin/bash

# Make passed variables a named variable
NSCONF=$1
DOMAIN=$2
DOMAINPASSWORD=$3
CERTS=$4
PFXPASS=$5

# Get MAC address of private subnet interface for LACP
MACADDRESS=`ifconfig 1/1 | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`

# Create LDAP string from domain name
DOMAINTOSPLIT=$DOMAIN
LDAPSTRING=""
IFS='.' read -a DOMAINARRAY <<< "${DOMAINTOSPLIT}"
for i in "${DOMAINARRAY[@]}"
do
   LDAPSTRING="${LDAPSTRING},dc=${i}"
done
# Remove first character
LDAPSTRING=${LDAPSTRING#?}

# Download the certificates zip file
curl --insecure -o /nsconfig/ssl/certificates.tar.gz $CERTS

# Unzip certificates
tar -zxvf /nsconfig/ssl/certificates.tar.gz -C /nsconfig/ssl

# Extract the certificate and key from PFX
openssl pkcs12 -in /nsconfig/ssl/wildcard.$DOMAIN.pfx -clcerts -nokeys -out /nsconfig/ssl/wildcard.$DOMAIN.cer -passin pass:$PFXPASS
openssl pkcs12 -in /nsconfig/ssl/wildcard.$DOMAIN.pfx -nocerts -nodes -out /nsconfig/ssl/wildcard.$DOMAIN_encrypted.key -passin pass:$PFXPASS
openssl rsa -in /nsconfig/ssl/wildcard.$DOMAIN_encrypted.key -out /nsconfig/ssl/wildcard.$DOMAIN.key

# Output the Netscaler configuration file
printf "" > $NSCONF
printf "#NS10.1 Build 121.14\n" >> $NSCONF
printf "# Created by custom scripts - https://github.com/willjasen/netscaler-bootstrap\n" >> $NSCONF
printf "set ns config -IPAddress 10.0.1.100 -netmask 255.255.255.0\n" >> $NSCONF
printf "set ns config -timezone \"GMT-05:00-EST-America/Jamaica\"\n" >> $NSCONF
printf "enable ns feature LB SSL SSLVPN REWRITE RESPONDER\n" >> $NSCONF
printf "enable ns mode FR L2 L3 CKA TCPB MBF Edge USNIP PMTUD\n" >> $NSCONF
printf "set system parameter -natPcbForceFlushLimit 4294967295\n" >> $NSCONF
printf "set system user nsroot $DOMAINPASSWORD -timeout 0\n" >> $NSCONF
printf "add system group Admins\n" >> $NSCONF
printf "set rsskeytype -rsstype ASYMMETRIC\n" >> $NSCONF
printf "set lacp -sysPriority 32768 -mac 06:21:81:19:a4:65\n" >> $NSCONF
printf "set interface 1/1 -throughput 0 -bandwidthHigh 0 -bandwidthNormal 0 -intftype \"Xen Virtual\" -ifnum 1/1\n" >> $NSCONF
printf "set interface 1/2 -throughput 0 -bandwidthHigh 0 -bandwidthNormal 0 -intftype \"Xen Virtual\" -ifnum 1/2\n" >> $NSCONF
printf "set interface LO/1 -haMonitor OFF -throughput 0 -bandwidthHigh 0 -bandwidthNormal 0 -intftype Loopback -ifnum LO/1\n" >> $NSCONF
printf "add vlan 2 -aliasName PublicDMZ\n" >> $NSCONF
printf "add ns ip6 fe80::1c6d:74ff:fe46:e532/64 -scope link-local -type NSIP -vlan 1 -vServer DISABLED -mgmtAccess ENABLED -dynamicRouting ENABLED\n" >> $NSCONF
printf "add ns ip 10.0.0.176 255.255.255.255 -type VIP -snmp DISABLED\n" >> $NSCONF
printf "add ns ip 10.0.1.102 255.255.255.0 -type MIP -vServer DISABLED -mgmtAccess ENABLED\n" >> $NSCONF
printf "add ns ip 10.0.1.108 255.255.255.255 -type VIP -snmp DISABLED\n" >> $NSCONF
printf "add ns ip 10.0.0.175 255.255.255.0 -type VIP -mgmtAccess ENABLED\n" >> $NSCONF
printf "add ns ip 10.0.1.50 255.255.255.0 -vServer DISABLED\n" >> $NSCONF
printf "set ipsec parameter -lifetime 28800\n" >> $NSCONF
printf "bind vlan 2 -ifnum 1/2\n" >> $NSCONF
printf "set nd6RAvariables -vlan 1\n" >> $NSCONF
printf "bind nd6RAvariables -vlan 1 -ipv6Prefix ::\n" >> $NSCONF
printf "set ipv6 -natprefix ::\n" >> $NSCONF
printf "add netProfile SFMIP -srcIP 10.0.1.102\n" >> $NSCONF
printf "set netProfile SFMIP -srcIP 10.0.1.102\n" >> $NSCONF
printf "set snmp alarm SYNFLOOD -timeout 1\n" >> $NSCONF
printf "set snmp alarm HA-VERSION-MISMATCH -time 86400 -timeout 86400\n" >> $NSCONF
printf "set snmp alarm HA-SYNC-FAILURE -time 86400 -timeout 86400\n" >> $NSCONF
printf "set snmp alarm HA-NO-HEARTBEATS -time 86400 -timeout 86400\n" >> $NSCONF
printf "set snmp alarm HA-BAD-SECONDARY-STATE -time 86400 -timeout 86400\n" >> $NSCONF
printf "set snmp alarm HA-PROP-FAILURE -timeout 86400\n" >> $NSCONF
printf "set snmp alarm IP-CONFLICT -timeout 86400\n" >> $NSCONF
printf "set snmp alarm APPFW-START-URL -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-DENY-URL -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-REFERER-HEADER -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-CSRF-TAG -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-COOKIE -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-FIELD-CONSISTENCY -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-BUFFER-OVERFLOW -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-FIELD-FORMAT -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-SAFE-COMMERCE -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-SAFE-OBJECT -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-POLICY-HIT -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-VIOLATIONS-TYPE -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XSS -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-XSS -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-SQL -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-SQL -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-ATTACHMENT -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-DOS -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-VALIDATION -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-WSI -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-SCHEMA-COMPILE -timeout 1\n" >> $NSCONF
printf "set snmp alarm APPFW-XML-SOAP-FAULT -timeout 1\n" >> $NSCONF
printf "set snmp alarm DNSKEY-EXPIRY -timeout 1\n" >> $NSCONF
printf "set snmp alarm HA-LICENSE-MISMATCH -timeout 86400\n" >> $NSCONF
printf "set snmp alarm CLUSTER-NODE-HEALTH -time 86400 -timeout 86400\n" >> $NSCONF
printf "set snmp alarm CLUSTER-NODE-QUORUM -time 86400 -timeout 86400\n" >> $NSCONF
printf "set snmp alarm CLUSTER-VERSION-MISMATCH -time 86400 -timeout 86400\n" >> $NSCONF
printf "add policy patset STORE_WEB_COOKIES10_0_0_176\n" >> $NSCONF
printf "bind policy patset ns_cvpn_default_inet_domains \"http://StoreFront.$DOMAIN\" -index 2\n" >> $NSCONF
printf "bind policy patset STORE_WEB_COOKIES10_0_0_176 CsrfToken -index 1\n" >> $NSCONF
printf "bind policy patset STORE_WEB_COOKIES10_0_0_176 ASP.NET_SessionId -index 2\n" >> $NSCONF
printf "bind policy patset STORE_WEB_COOKIES10_0_0_176 CtxsPluginAssistantState -index 3\n" >> $NSCONF
printf "bind policy patset STORE_WEB_COOKIES10_0_0_176 CtxsAuthId -index 4\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_tcp_lfp -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_tcp_lnp -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_tcp_lan -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_tcp_lfp_thin_stream -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_tcp_lnp_thin_stream -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_tcp_lan_thin_stream -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_tcp_interactive_stream -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_internal_apps -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_XA_XD_profile -mss 0\n" >> $NSCONF
printf "set ns tcpProfile nstcp_default_Mobile_profile -mss 0\n" >> $NSCONF
printf "add server DC1.$DOMAIN 10.0.1.5\n" >> $NSCONF
printf "add server DC2.$DOMAIN 10.0.1.6\n" >> $NSCONF
printf "add server XenAppDC1.$DOMAIN 10.0.1.7\n" >> $NSCONF
printf "add server StoreFront.$DOMAIN 10.0.1.9\n" >> $NSCONF
printf "add service XenAppDC1 XenAppDC1.$DOMAIN TCP 80 -gslb NONE -maxClient 0 -maxReq 0 -cip DISABLED -usip NO -useproxyport YES -sp OFF -cltTimeout 9000 -svrTimeout 9000 -CustomServerID \"\\\"None\\\"\" -CKA YES -TCPB YES -CMP NO\n" >> $NSCONF
printf "add service XenAppDC1-8080 XenAppDC1.$DOMAIN TCP 8080 -gslb NONE -maxClient 0 -maxReq 0 -cip DISABLED -usip NO -useproxyport YES -sp OFF -cltTimeout 9000 -svrTimeout 9000 -CustomServerID \"\\\"None\\\"\" -CKA YES -TCPB YES -CMP NO\n" >> $NSCONF
printf "add serviceGroup StoreFront_svcg HTTP -maxClient 0 -maxReq 0 -cip ENABLED X-Forwarded-For -usip NO -useproxyport YES -sp ON -cltTimeout 180 -svrTimeout 360 -CKA NO -TCPB NO -CMP NO -appflowLog DISABLED\n" >> $NSCONF
printf "add aaa user localadmin -password fd2604527edf7371a2 -encrypted\n" >> $NSCONF
printf "set aaa ldapParams -serverIP 10.0.1.5 -ldapBase \"$LDAPSTRING\" -ldapBindDn administrator@$DOMAIN -ldapBindDnPassword $DOMAINPASSWORD\n" >> $NSCONF
printf "add ssl certKey ns-server-certificate -cert ns-server.cert -key ns-server.key\n" >> $NSCONF
printf "add ssl certKey wildcard.$DOMAIN -cert wildcard.$DOMAIN.cer -key \"/nsconfig/ssl/wildcard.$DOMAIN.key\"\n" >> $NSCONF
printf "add ssl certKey Intermediate -cert Intermediate.cer -inform DER\n" >> $NSCONF
printf "add ssl certKey Root -cert Root.cer -inform DER\n" >> $NSCONF
printf "link ssl certKey wildcard.$DOMAIN Intermediate\n" >> $NSCONF
printf "link ssl certKey Intermediate Root\n" >> $NSCONF
printf "add authentication ldapAction DC1 -serverIP 10.0.1.5 -serverPort 636 -ldapBase \"$LDAPSTRING\" -ldapBindDn administrator@$DOMAIN -ldapBindDnPassword $DOMAINPASSWORD -ldapLoginName samAccountName -groupAttrName memberOf -subAttributeName CN -secType SSL -passwdChange ENABLED\n" >> $NSCONF
printf "add authentication ldapAction DC2 -serverIP 10.0.1.6 -serverPort 636 -ldapBase \"$LDAPSTRING\" -ldapBindDn administrator@$DOMAIN -ldapBindDnPassword $DOMAINPASSWORD -ldapLoginName samAccountName -groupAttrName memberOf -subAttributeName CN -secType SSL -passwdChange ENABLED\n" >> $NSCONF
printf "bind cmp global ns_adv_nocmp_xml_ie -priority 8700 -gotoPriorityExpression END -type RES_DEFAULT\n" >> $NSCONF
printf "bind cmp global ns_adv_nocmp_mozilla_47 -priority 8800 -gotoPriorityExpression END -type RES_DEFAULT\n" >> $NSCONF
printf "bind cmp global ns_adv_cmp_mscss -priority 8900 -gotoPriorityExpression END -type RES_DEFAULT\n" >> $NSCONF
printf "bind cmp global ns_adv_cmp_msapp -priority 9000 -gotoPriorityExpression END -type RES_DEFAULT\n" >> $NSCONF
printf "bind cmp global ns_adv_cmp_content_type -priority 10000 -gotoPriorityExpression END -type RES_DEFAULT\n" >> $NSCONF
printf "add authentication localPolicy LocalAuth ns_true\n" >> $NSCONF
printf "add authentication ldapPolicy 10.0.1.5_LDAP_policy NS_TRUE 10.0.1.5_LDAP\n" >> $NSCONF
printf "add authentication ldapPolicy LDAP1 NS_TRUE DC1\n" >> $NSCONF
printf "add authentication ldapPolicy LDAP2 ns_true DC2\n" >> $NSCONF
printf "add authorization policy auth_allow_access ns_true ALLOW\n" >> $NSCONF
printf "set lb parameter -sessionsThreshold 150000\n" >> $NSCONF
printf "add lb vserver StoreFront_vServer1 HTTP 10.0.1.108 80 -persistenceType COOKIEINSERT -cltTimeout 180 -netProfile SFMIP\n" >> $NSCONF
printf "add lb vserver 10.0.0.176http_redirect HTTP 10.0.0.176 80 -persistenceType COOKIEINSERT -redirectURL \"https://10.0.0.176\" -cltTimeout 180\n" >> $NSCONF
printf "set cs parameter -stateupdate ENABLED\n" >> $NSCONF
printf "set cache parameter -via \"NS-CACHE-10.0: 100\"\n" >> $NSCONF
printf "set aaa parameter -maxAAAUsers 5\n" >> $NSCONF
printf "add vpn vserver AGEE SSL 10.0.0.176 443 -maxAAAUsers 99 -icaOnly ON\n" >> $NSCONF
printf "set ns rpcNode 10.0.1.100 -password 8a7b474124957776a0cd31b862cbe4d72b5cbd59868a136d4bdeb56cf03b28 -encrypted -srcIP *\n" >> $NSCONF
printf "add vpn clientlessAccessProfile STORE_WEB_REWRITE_10.0.0.176\n" >> $NSCONF
printf "add vpn clientlessAccessProfile no_rewrite_10.0.0.176\n" >> $NSCONF
printf "set vpn clientlessAccessProfile STORE_WEB_REWRITE_10.0.0.176 -URLRewritePolicyLabel ns_cvpn_default_inet_url_label -ClientConsumedCookies STORE_WEB_COOKIES10_0_0_176\n" >> $NSCONF
printf "add vpn clientlessAccessPolicy CLIENTLESS_RF_POL_10.0.0.176 TRUE STORE_WEB_REWRITE_10.0.0.176\n" >> $NSCONF
printf "add vpn clientlessAccessPolicy CLIENTLESS_POL_10.0.0.176 \"HTTP.REQ.HEADER(\\\"User-Agent\\\").CONTAINS(\\\"CitrixReceiver\\\") && HTTP.REQ.HEADER(\\\"X-Citrix-Gateway\\\").EXISTS\" no_rewrite_10.0.0.176\n" >> $NSCONF
printf "set responder param -undefAction NOOP\n" >> $NSCONF
printf "bind lb vserver StoreFront_vServer1 StoreFront_svcg\n" >> $NSCONF
printf "add dns nameServer 10.0.1.5\n" >> $NSCONF
printf "add dns nameServer 10.0.1.6\n" >> $NSCONF
printf "set ns diameter -identity netscaler.com -realm com\n" >> $NSCONF
printf "set dns parameter -dns64Timeout 1000\n" >> $NSCONF
printf "add dns nsRec . a.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . b.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . c.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . d.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . e.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . f.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . g.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . h.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . i.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . j.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . k.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . l.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns nsRec . m.root-servers.net -TTL 3600000\n" >> $NSCONF
printf "add dns addRec l.root-servers.net 199.7.83.42 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec b.root-servers.net 192.228.79.201 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec d.root-servers.net 128.8.10.90 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec d.root-servers.net 199.7.91.13 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec j.root-servers.net 192.58.128.30 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec h.root-servers.net 128.63.2.53 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec f.root-servers.net 192.5.5.241 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec k.root-servers.net 193.0.14.129 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec a.root-servers.net 198.41.0.4 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec c.root-servers.net 192.33.4.12 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec m.root-servers.net 202.12.27.33 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec i.root-servers.net 192.36.148.17 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec g.root-servers.net 192.112.36.4 -TTL 3600000\n" >> $NSCONF
printf "add dns addRec e.root-servers.net 192.203.230.10 -TTL 3600000\n" >> $NSCONF
printf "add dns suffix $DOMAIN\n" >> $NSCONF
printf "set lb monitor ping PING -LRTM DISABLED -interval 1 MIN\n" >> $NSCONF
printf "set lb monitor dns DNS -query dc1.$DOMAIN -LRTM DISABLED -interval 1 MIN -resptimeout 5 -IPAddress 10.0.1.5\n" >> $NSCONF
printf "set lb monitor ldns-dns LDNS-DNS -query . -queryType Address\n" >> $NSCONF
printf "add lb monitor citric-xml-notepad CITRIX-XML-SERVICE -LRTM ENABLED -application Notepad\n" >> $NSCONF
printf "bind service XenAppDC1-8080 -monitorName tcp\n" >> $NSCONF
printf "bind service XenAppDC1 -monitorName tcp\n" >> $NSCONF
printf "bind serviceGroup StoreFront_svcg StoreFront.$DOMAIN 80 -CustomServerID \"\\\"None\\\"\"\n" >> $NSCONF
printf "add route 0.0.0.0 0.0.0.0 10.0.1.1\n" >> $NSCONF
printf "set ssl parameter -denySSLReneg FRONTEND_CLIENT\n" >> $NSCONF
printf "set ssl service vpndbssvc_873482992 -sessReuse ENABLED -sessTimeout 120 -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl service nshttps-10.0.1.102-443 -eRSA ENABLED -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl service nsrpcs-10.0.1.102-3008 -eRSA ENABLED -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl service nshttps-::1l-443 -eRSA ENABLED -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl service nsrpcs-::1l-3008 -eRSA ENABLED -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl service nskrpcs-127.0.0.1-3009 -eRSA ENABLED -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl service nshttps-127.0.0.1-443 -eRSA ENABLED -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl service nsrpcs-127.0.0.1-3008 -eRSA ENABLED -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "set ssl vserver AGEE -sessReuse DISABLED -tls11 DISABLED -tls12 DISABLED\n" >> $NSCONF
printf "add vpn sessionAction ACT_PNA_10.0.0.176 -defaultAuthorizationAction ALLOW -SSO ON -ssoCredential PRIMARY -icaProxy ON -wihome \"http://10.0.1.108/Citrix/XenAppCloud\" -ntDomain $DOMAIN -clientlessVpnMode ON -storefronturl \"http://10.0.1.108/Citrix/Authentication/auth/v1/token/validate\"\n" >> $NSCONF
printf "add vpn sessionAction ACT_OS_10.0.0.176 -defaultAuthorizationAction ALLOW -SSO ON -icaProxy OFF -wihome \"http://10.0.1.108/Citrix/XenAppCloudWeb\" -ntDomain $DOMAIN -clientlessVpnMode ON -clientlessModeUrlEncoding TRANSPARENT -storefronturl \"http://10.0.1.108/Citrix/Authentication/auth/v1/token/validate\"\n" >> $NSCONF
printf "add vpn sessionAction ACT_WEB_10.0.0.176 -defaultAuthorizationAction ALLOW -SSO ON -homePage \"http://10.0.1.108/Citrix/XenAppCloudWeb\" -icaProxy OFF -wihome \"http://10.0.1.108/Citrix/XenAppCloudWeb\" -ClientChoices OFF -ntDomain $DOMAIN -clientlessVpnMode ON -storefronturl \"http://10.0.1.108/Citrix/Authentication/auth/v1/token/validate\"\n" >> $NSCONF
printf "add vpn sessionAction ACT_AG_PLUGIN_10.0.0.176 -splitTunnel ON -defaultAuthorizationAction ALLOW -icaProxy OFF -wihome \"http://10.0.1.108/Citrix/XenAppCloudWeb\" -storefronturl \"http://10.0.1.108/Citrix/Authentication/auth/v1/token/validate\"\n" >> $NSCONF
printf "add vpn sessionAction SSLVPN_Storefront_Pro -sessTimeout 120 -defaultAuthorizationAction ALLOW -SSO ON -ssoCredential PRIMARY -icaProxy ON -wihome \"https://StoreFront.$DOMAIN/Citrix/XenAppWeb\" -ntDomain $DOMAIN -clientlessVpnMode OFF -clientlessModeUrlEncoding OPAQUE -storefronturl \"https://StoreFront.$DOMAIN\"\n" >> $NSCONF
printf "add vpn sessionAction NativeReceiver -sessTimeout 120 -transparentInterception OFF -defaultAuthorizationAction ALLOW -SSO ON -ssoCredential PRIMARY -icaProxy ON -wihome \"https://StoreFront.$DOMAIN/\" -ntDomain $DOMAIN -clientlessVpnMode OFF -storefronturl \"https://StoreFront.$DOMAIN/Citrix/Roaming/Accounts\"\n" >> $NSCONF
printf "add vpn sessionPolicy POLICY_PNA_10.0.0.176 \"REQ.HTTP.HEADER User-Agent CONTAINS CitrixReceiver && REQ.HTTP.HEADER X-Citrix-Gateway NOTEXISTS\" ACT_PNA_10.0.0.176\n" >> $NSCONF
printf "add vpn sessionPolicy POLICY_OS_10.0.0.176 \"REQ.HTTP.HEADER User-Agent CONTAINS CitrixReceiver && REQ.HTTP.HEADER X-Citrix-Gateway EXISTS\" ACT_OS_10.0.0.176\n" >> $NSCONF
printf "add vpn sessionPolicy POLICY_WEB_10.0.0.176 \"REQ.HTTP.HEADER User-Agent NOTCONTAINS CitrixReceiver && REQ.HTTP.HEADER Referer EXISTS\" ACT_WEB_10.0.0.176\n" >> $NSCONF
printf "add vpn sessionPolicy POLICY_AG_PLUGIN_10.0.0.176 \"REQ.HTTP.HEADER User-Agent NOTCONTAINS CitrixReceiver && REQ.HTTP.HEADER Referer NOTEXISTS\" ACT_AG_PLUGIN_10.0.0.176\n" >> $NSCONF
printf "add vpn sessionPolicy SSLVPN_Storefront_Pol \"REQ.HTTP.HEADER User-Agent NOTCONTAINS CitrixReceiver && REQ.HTTP.HEADER Referer EXISTS\" SSLVPN_Storefront_Pro\n" >> $NSCONF
printf "add vpn sessionPolicy \"NativeReceiver Policy\" \"REQ.HTTP.HEADER User-Agent CONTAINS CitrixReceiver && REQ.HTTP.HEADER X-Citrix-Gateway EXISTS\" NativeReceiver\n" >> $NSCONF
printf "add vpn sessionPolicy Test ns_true SSLVPN_Storefront_Pro\n" >> $NSCONF
printf "add vpn sessionPolicy SF_Web \"REQ.HTTP.HEADER User-Agent NOTCONTAINS CitrixReceiver && REQ.HTTP.HEADER Referer EXISTS\" SSLVPN_Storefront_Pro\n" >> $NSCONF
printf "set vpn parameter -sessTimeout 120 -defaultAuthorizationAction ALLOW -proxy OFF -forceCleanup none -clientOptions all -clientConfiguration all -SSO ON -windowsAutoLogon ON -icaProxy ON -wihome \"https://storefront.$DOMAIN/Citrix/XenAppWeb\" -wiPortalMode NORMAL -ntDomain $DOMAIN -clientlessVpnMode DISABLED -clientlessModeUrlEncoding TRANSPARENT -clientlessPersistentCookie ALLOW -UITHEME DEFAULT\n" >> $NSCONF
printf "bind aaa user localadmin -policy auth_allow_access -priority 100\n" >> $NSCONF
printf "bind aaa user localadmin -policy POLICY_WEB_10.0.0.176 -priority 100\n" >> $NSCONF
printf "bind system group Admins -policyName superuser 0\n" >> $NSCONF
printf "bind system global 10.0.1.5_LDAP_policy\n" >> $NSCONF
printf "bind system global LocalAuth\n" >> $NSCONF
printf "bind vpn global -policyName 10.0.1.5_LDAP_policy -priority 100\n" >> $NSCONF
printf "bind vpn global -policyName LocalAuth -priority 110\n" >> $NSCONF
printf "bind vpn global -intranetDomain $DOMAIN\n" >> $NSCONF
printf "bind vpn vserver AGEE -staServer \"http://XenAppDC1.$DOMAIN\"\n" >> $NSCONF
printf "bind vpn vserver AGEE -policy LDAP1 -priority 10\n" >> $NSCONF
printf "bind vpn vserver AGEE -policy LDAP2 -priority 20\n" >> $NSCONF
printf "bind vpn vserver AGEE -policy \"NativeReceiver Policy\" -priority 10\n" >> $NSCONF
printf "bind vpn vserver AGEE -policy SF_Web -priority 20\n" >> $NSCONF
printf "bind ssl service nshttps-10.0.1.102-443 -certkeyName ns-server-certificate\n" >> $NSCONF
printf "bind ssl service nsrpcs-10.0.1.102-3008 -certkeyName ns-server-certificate\n" >> $NSCONF
printf "bind ssl service nshttps-::1l-443 -certkeyName ns-server-certificate\n" >> $NSCONF
printf "bind ssl service nsrpcs-::1l-3008 -certkeyName ns-server-certificate\n" >> $NSCONF
printf "bind ssl service nskrpcs-127.0.0.1-3009 -certkeyName ns-server-certificate\n" >> $NSCONF
printf "bind ssl service nshttps-127.0.0.1-443 -certkeyName ns-server-certificate\n" >> $NSCONF
printf "bind ssl service nsrpcs-127.0.0.1-3008 -certkeyName ns-server-certificate\n" >> $NSCONF
printf "bind ssl vserver AGEE -certkeyName wildcard.$DOMAIN\n" >> $NSCONF
printf "set ns encryptionParams -method AES256 -keyValue ff0e316156e61473c6bd67cd2f8c8389270dab4df88f4e5e10ddd34c9f6f6b27bbd5b6745fc9171b8742e962ba2f16b061c112b8 -encrypted\n" >> $NSCONF
printf "set inatparam -nat46v6Prefix ::/96\n" >> $NSCONF
printf "set ip6TunnelParam -srcIP ::\n" >> $NSCONF
printf "set ptp -state ENABLE\n" >> $NSCONF
printf "set ns param -timezone \"GMT-05:00-EST-America/Jamaica\"\n" >> $NSCONF
