# Flytrap
 
A TCP honeyport built for attacker detection post-network infiltration. When a connection is made to the port Flytrap is 
listening on, Flytrap will block the attacker by default and send a critical syslog message to the specified syslog 
server. It's recommended you feed this into your SIEM to alert the SOC that an intrusion may have occurred.

Requires Python 3.8 or higher.

Works on Windows and Linux, as well as with IPv4 and IPv6.

To use the tool, simply run python3 flytrap.py. Flytrap requires root permissions in order to manipulate the system 
firewall. Pressing enter will select the default options listed in brackets. 

Here's a breakdown of the options presented in the menu:

**Local IP:** an IP address that exists on the system. Flytrap will detect an IPv4 address on the local system that can 
reach the rest of the network, and provide it as default. If you're using IPv6, do not use a link-local IP address 
(starts with FE80) here.

**TCP port:** Enter a valid TCP port (between ports 0 and 65535) to use as your listener. The default here is 9000. 
Consider  using something interesting that would entice an attacker to take a look.

**Mode:** Active mode will add firewall rules in supported firewalls (Windows Defender, firewalld, iptables, and ufw) to 
block the attacker from accessing the local system when a connection is made to the TCP port specified. Passive mode 
will not block the attacker. Both modes send a syslog message.

**Syslog server:** Set this to the IP of your Syslog server. It's highly recommended that this be a separate device and
not running on the same system as Flytrap. This defaults to 127.0.0.1.

**Syslog port:** This is the remote port that the syslog service will be listening on to receive any syslog messages 
sent. Default is 514.

Please report any issues encountered by creating an issue on github.
