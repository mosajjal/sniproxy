#!/bin/bash
# A simple script to install sniproxy on a Linux system
# This script is intended to be run on a fresh install of Debian or Redhat based systems
# It will install sniproxy and its dependencies, and set it up as a systemd service
# It will also configure the system to use sniproxy as the default DNS resolver
# For more information, please visit https://github.com/mosajjal/sniproxy

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# log functions
log() {
    echo -e "[${GREEN}INFO${NC}] $1" >&2
}

warn() {
    echo -e "[${YELLOW}WARNING${NC}] $1" >&2
}

success() {
    echo -e "[${GREEN}SUCCESS${NC}] $1" >&2
}

fail() {
    echo -e "[${RED}ERROR${NC}] $1" >&2
    exit 1
}

# Function to get the latest release from GitHub
get_latest_release() {
    log "Getting latest release for $1"
    curl --silent "https://api.github.com/repos/$1/releases/latest" | # Get latest release from GitHub api
        grep '"tag_name":' |                                          # Get tag line
        sed -E 's/.*"([^"]+)".*/\1/'                                  # Pluck JSON value
}

# Function to download a file with retries
download_file() {
    local url=$1
    local output=$2
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        curl -L -o "$output" "$url"
        if [ $? -eq 0 ]; then
            success "Downloaded $url to $output"
            return 0
        else
            attempts=$((attempts + 1))
            warn "Download attempt $attempts failed, retrying..."
            if [ $attempts -ge $max_attempts ]; then
                fail "Failed to download $url after $max_attempts attempts"
            fi
            sleep 2
        fi
    done
}

log "Starting sniproxy installation..."

# check distro and root
if [ -f /etc/debian_version ]; then
    echo "Debian/Ubuntu detected"
    if [ "$(id -u)" != "0" ]; then
        fail "This script must be run as root" 1>&2
    fi
elif [ -f /etc/redhat-release ]; then
    echo "Redhat/CentOS detected"
    if [ "$(id -u)" != "0" ]; then
        fail "This script must be run as root" 1>&2
    fi
else
    fail "Unsupported distro"
fi

# check to see if the OS is systemd-based
if [ ! -d /run/systemd/system ]; then
    fail "Systemd not detected, exiting"
fi

# check for dependencies
if ! command -v curl &> /dev/null; then
    log "curl could not be found, installing..."
    if [ -f /etc/debian_version ]; then
        apt-get update && apt-get install -y curl
    elif [ -f /etc/redhat-release ]; then
        yum install -y curl
    fi
fi
success "Prerequisites installed successfully"

# detect platform
platform=""
case $(uname -m) in
"x86_64") platform="linux-amd64" ;;
"aarch64") platform="linux-arm64" ;;
*) fail "Unsupported platform" ;;
esac
log "Detected platform: $platform"

# create a folder under /opt for sniproxy
log "Creating installation directory: /opt/sniproxy"
mkdir -p /opt/sniproxy

execCommand="/opt/sniproxy/sniproxy"
configPath="/opt/sniproxy/sniproxy.yaml"
yqPath="/opt/sniproxy/yq"

# download sniproxy
log "Fetching latest release information..."
latest_tag=$(get_latest_release "mosajjal/sniproxy")
success "Latest release tag: $latest_tag"
download_url="https://github.com/mosajjal/sniproxy/releases/download/$latest_tag/sniproxy-$latest_tag-$platform.tar.gz"
log "Downloading sniproxy binary..."
log "URL: $download_url"
temp_file="/tmp/sniproxy.tar.gz"
download_file "$download_url" "$temp_file"
tar -xzf "$temp_file" -C /opt/sniproxy/
mv /opt/sniproxy/sniproxy-$latest_tag-$platform/sniproxy $execCommand
rm -rf /opt/sniproxy/sniproxy-$latest_tag-$platform
rm "$temp_file"

# make it executable
chmod +x $execCommand

# download yq
log "Downloading yq..."
yq_latest_tag=$(get_latest_release "mikefarah/yq")
success "Latest yq release tag: $yq_latest_tag"
yq_download_url="https://github.com/mikefarah/yq/releases/download/$yq_latest_tag/yq_linux_amd64"
log "URL: $yq_download_url"
download_file "$yq_download_url" "$yqPath"

# make it executable
chmod +x $yqPath

# generate the default config
log "Generating default config..."
$execCommand --defaultconfig >$configPath
success "Default config generated at $configPath"

# prompt before removing stub resolver
warn "This script can remove the stub resolver from /etc/resolv.conf and replace it with a DNS of your choice."
warn "This is recommended for the best performance, but it might break some applications that rely on the stub resolver."
echo "Do you want to remove the stub resolver? (y/n)"
read removeStubResolver

if [ "$removeStubResolver" = "y" ]; then
    echo "Press Enter to use 9.9.9.9 as the DNS server, otherwise enter your preferred DNS server and press Enter"
    read dnsServer

    # if dnsServer is empty, replace it with 9.9.9.9
    if [ -z "$dnsServer" ]; then
        dnsServer="9.9.9.9"
    fi

    # check to see if sed is installed
    if ! command -v sed &>/dev/null; then
        fail "sed could not be found"
    fi

    # remove stub resolver
    log "Removing stub resolver..."
    sed -i 's/#DNS=/DNS='$dnsServer'/; s/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
    success "Stub resolver removed"

    # check if stub resolver is removed by checking netstat for port 53 udp. try both ss and netstat
    # try ss first, if it's not installed, try netstat
    if command -v ss &>/dev/null; then
        if ss -lunp | grep -q ":53 "; then
            warn "stub resolver might not be removed. maybe sniproxy is already installed?"
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -lunp | grep -q ":53 "; then
            warn "stub resolver might not be removed. maybe sniproxy is already installed?"
        fi
    else
        warn "ss and netstat could not be found, can't verify stub resolver status"
    fi
fi

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
log "Creating systemd service file..."
cat <<EOF >/etc/systemd/system/sniproxy.service
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
success "Systemd service file created"

# enable and start the service
log "Enabling and starting sniproxy service..."
systemctl daemon-reload
systemctl enable sniproxy
systemctl start sniproxy

# check if sniproxy is running
if systemctl is-active --quiet sniproxy; then
    success "sniproxy is running"
else
    fail "sniproxy is not running. check logs with 'journalctl -u sniproxy'"
fi

# get the public IP of the server by curl 4.ident.me
publicIP=$(curl -s 4.ident.me)

# print some instructions for setting up DNS in clients to this
echo "sniproxy is now running, you can set up DNS in your clients to $publicIP"
echo "you can check the status of sniproxy by running: sudo systemctl status sniproxy"
echo "you can check the logs of sniproxy by running: sudo journalctl -u sniproxy"
echo "some of the features of sniproxy are not covered by this script, please refer to the GitHub page for more information: github.com/mosajjal/sniproxy"

echo "if journal shows empty, you might need to reboot the server, sniproxy is set up as a service so it should start automatically after reboot"

# we're done
success "Done"
exit 0
