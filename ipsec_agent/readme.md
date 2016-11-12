# IPSEC Agent
Control the strongswan process and configuration. Provide a REST API for getting status information

## Notes
* In order for vici to work, strongswan must be compiled with the --enable-vici configure option, and the socket path for the vici plugin explicitly set in /etc/strongswan.d/charon/plugins/vici.conf
