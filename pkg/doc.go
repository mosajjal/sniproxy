/*
Continuation of [byosh] and [SimpleSNIProxy] projects.

# pre-requisites

To ensure that Sniproxy works correctly, it's important to have ports 80, 443, and 53 open.
However, on Ubuntu, it's possible that port 53 may be in use by systemd-resolved.
To disable systemd-resolved and free up the port, follow [these instructions].

If you prefer to keep systemd-resolved and just disable the built-in resolver, you can use the following command:

	sed -i 's/#DNS=/DNS=9.9.9.9/; s/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
	systemctl restart systemd-resolved

# How to Install

The simplest way to install the software is by utilizing the pre-built binaries available on the releases page.
Alternatively, there are other ways to install, which include:

Using "go install" command:

	go install github.com/mosajjal/sniproxy/v2@latest

Using Docker or Podman:

	docker run -d --pull always -p 80:80 -p 443:443 -p 53:53/udp -v "$(pwd)/config.defaults.yaml:/tmp/config.yaml" ghcr.io/mosajjal/sniproxy:latest --config /tmp/config.yaml

Using the installer script:

	bash <(curl -L https://raw.githubusercontent.com/mosajjal/sniproxy/master/install.sh)

# How to Run

sniproxy can be configured using a configuration file or environment variables
The configuration file is a YAML file, and an example configuration file can be found under [Sample config file].
you can find the instructions for the environment variables there as well.

	sniproxy [flags]

	Flags:

		-c, --config string   path to YAML configuration file
			--defaultconfig   write the default config yaml file to stdout
		-h, --help            help for sniproxy
		-v, --version         show version info and exit

# Setting Up an SNI Proxy Using Vultr

In this tutorial, we will go over the steps to set up an SNI proxy using Vultr as a service provider. This will allow you to serve multiple SSL-enabled websites from a single IP address.

# Prerequisites

- A Vultr account. If you don't have one, you can sign up for free using my [Vultr referal link]

## Step 1: Create a Vultr Server

First, log in to your Vultr account and click on the "Instances" tab in the top menu. Then, click the "+" button to deploy a new server.

On the "Deploy New Instance" page, select the following options:

- Choose Server: Choose "Cloud Compute"
- CPU & Storage Technology: Any of the choices should work perfectly fine
- Server Location: Choose the location of the server. This will affect the latency of your website, so it's a good idea to choose a location that is close to your target audience.
- Server Image: Any OS listed there is supported. If you're not sure what to choose, Ubuntu is a good option
- Server Size: Choose a server size that is suitable for your needs. A small or medium-sized server should be sufficient for most SNI proxy setups. Pay attention to the monthly bandwidth usage as well
- "Add Auto Backups": not strictly needed for sniproxy.
- "SSH Keys": choose a SSH key to facilitate logging in later on. you can always use Vultr's builtin console as well.
- Server Hostname: Choose a hostname for your server. This can be any name you like.
After you have selected the appropriate options, click the "Deploy Now" button to create your server.

## Step 2: Install the SNI Proxy

Once your server has been created, log in to the server using SSH or console. The root password is available under the "Overview" tab in instances list.

Ensure the firewall (firewalld, ufw or iptables) is allowing connectivity to ports 80/TCP, 443/TCP and 53/UDP. For `ufw`, allow these ports with:

	sudo ufw allow 80/tcp
	sudo ufw allow 443/tcp
	sudo ufw allow 53/udp
	sudo ufw reload

once you have a shell in front of you, run the following (assuming you're on Ubuntu 22.04)

	bash <(curl -L https://raw.githubusercontent.com/mosajjal/sniproxy/master/install.sh)

above script is an interactive installer, it will ask you a few questions and then install sniproxy for you. it also installs sniproxy as a systemd servers, and enables it to start on boot.

# step 3: customize your configuration

above wizard will set up execution arguments for sniproxy. you can edit them by running

	sudo vim /opt/sniproxy/sniproxy.yaml

and edit parameters as you see fit. for example, you can add more domains to the list of domains to proxy, or change the port numbers.

[byosh]: https://github.com/mosajjal/byosh
[SimpleSNIProxy]: https://github.com/ziozzang/SimpleSNIProxy
[these instructions]: https://gist.github.com/zoilomora/f7d264cefbb589f3f1b1fc2cea2c844c
[Vultr referal link]: https://www.vultr.com/?ref=8578601
[Sample config file]: ./config.sample.yaml
*/
package sniproxy
