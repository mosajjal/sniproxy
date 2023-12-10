#!/bin/bash
set -e

# check distro and root
if [ -f /etc/debian_version ]; then
    echo "Debian/Ubuntu detected"
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi
elif [ -f /etc/redhat-release ]; then
    echo "Redhat/CentOS detected"
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi
else
    echo "Unsupported distro"
    exit 1
fi

# check to see if the OS is systemd-based
if [ ! -d /run/systemd/system ]; then
    echo "Systemd not detected, exiting"
    exit 1
fi

# prompt before removing stub resolver
echo "This script will remove the stub resolver from /etc/resolv.conf"
echo "and replace it with 9.9.9.9"
echo "Press Ctrl-C to abort or Enter to replace the DNS server with 9.9.9.9, otherwise enter your preffered DNS server and press Enter"
read dnsServer

# if dnsServer is empty, replace it with 9.9.9.9
if [ -z "$dnsServer" ]; then
    dnsServer="9.9.9.9"
fi

# check to see if sed is installed
if ! command -v sed &> /dev/null; then
    echo "sed could not be found"
    exit 1
fi

# remove stub resolver
sed -i 's/#DNS=/DNS='$dnsServer'/; s/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
systemctl restart systemd-resolved

# check if stub resolver is removed by checking netstat for port 53 udp. try both ss and netstat
# try ss first, if it's not installed, try netstat
if command -v ss &> /dev/null; then
    if ss -lun '( dport = :53 )' | grep -q 53; then
        echo "stub resolver is not removed"
        exit 1
    fi
elif command -v netstat &> /dev/null; then
    if netstat -lun '( dport = :53 )' | grep -q 53; then
        echo "stub resolver is not removed. maybe sniproxy is already installed?"
        exit 1
    fi
else
    echo "ss and netstat could not be found"
    exit 1
fi

# create a folder under /opt for sniproxy
mkdir -p /opt/sniproxy

execCommand="/opt/sniproxy/sniproxy"
configPath="/opt/sniproxy/sniproxy.yaml"
yqPath="/opt/sniproxy/yq"

# download sniproxy
curl -L -o $execCommand http://bin.n0p.me/sniproxy
# make it executable
chmod +x $execCommand

# download yq
curl -L -o $yqPath http://bin.n0p.me/yq
# make it executable
chmod +x $yqPath

# generate the default config
$execCommand --defaultconfig > $configPath

# ask which domains to proxy
echo "sniproxy can proxy all HTTPS traffic or only specific domains, if you have a domain list URL, enter it below, otherwise press Enter to proxy all HTTPS traffic"
read domainlist

# if domainslist is not empty, there should be a --domainListPath argument added to sniproxy execute command
if [ -n "$domainlist" ]; then
    $yqPath -i '.acl.domain.enabled = true, .acl.domain.path = '"$domainlist" $configPath
fi

# ask if DNS over TCP should be enabled
echo "Do you want to enable DNS over TCP? (y/n)"
read dnsOverTCP
# if yes, add --bindDnsOverTcp argument to sniproxy execute command
if [ "$dnsOverTCP" = "y" ]; then
    $yqPath -i '.general.bind_dns_over_tcp = "0.0.0.0:53"' $configPath
fi

# ask if DNS over TLS should be enabled
echo "Do you want to enable DNS over TLS? (y/n)"
read dnsOverTLS
# if yes, add --bindDnsOverTls argument to sniproxy execute command
if [ "$dnsOverTLS" = "y" ]; then
    $yqPath -i '.general.bind_dns_over_tls = "0.0.0.0:853"' $configPath
fi

# ask for DNS over QUIC
echo "Do you want to enable DNS over QUIC? (y/n)"
read dnsOverQUIC
# if yes, add --bindDnsOverQuic argument to sniproxy execute command
if [ "$dnsOverQUIC" = "y" ]; then
    $yqPath -i '.general.bind_dns_over_quic = "0.0.0.0:8853"' $configPath
fi

# if any of DNS over TLS or DNS over QUIC is enabled, ask for the certificate path and key path
if [ "$dnsOverTLS" = "y" ] || [ "$dnsOverQUIC" = "y" ]; then
    echo "Enter the path to the certificate file, if you don't have one, press Enter to use a self-signed certificate"
    read certPath
    echo "Enter the path to the key file, if you don't have one, press Enter to use a self-signed certificate"
    read keyPath

    # if any of the paths are empty, omit both arguments and print a warning for self-signed certificates
    if [ -z "$certPath" ] || [ -z "$keyPath" ]; then
        echo "WARNING: Using self-signed certificates"
    else
        $yqPath -i '.general.tls_cert = "$certPath", .general.tls_key = "$keyPath"' $configPath
    fi
fi

# create a systemd service file
cat <<EOF > /etc/systemd/system/sniproxy.service
[Unit]
Description=sniproxy
After=network.target

[Service]
Type=simple
ExecStart=$execCommand --config $configPath
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# enable and start the service
systemctl enable sniproxy
systemctl start sniproxy

# check if sniproxy is running
if systemctl is-active --quiet sniproxy; then
    echo "sniproxy is running"
else
    echo "sniproxy is not running"
fi

# get the public IP of the server by curl 4.ident.me
publicIP=$(curl -s 4.ident.me)

# print some instructions for setting up DNS in clients to this
echo "sniproxy is now running, you can set up DNS in your clients to $publicIP"
echo "you can check the status of sniproxy by running: sudo systemctl status sniproxy"
echo "you can check the logs of sniproxy by running: sudo journalctl -u sniproxy"
echo "some of the features of sniproxy are not covered by this script, please refer to the GitHub page for more information: github.com/moasjjal/sniproxy"

echo "if journal shows empty, you might need to reboot the server, sniproxy is set up as a service so it should start automatically after reboot"

# we're done
echo "Done"
exit 0
