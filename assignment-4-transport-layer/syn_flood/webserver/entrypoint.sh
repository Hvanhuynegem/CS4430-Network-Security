#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
httpd-foreground
