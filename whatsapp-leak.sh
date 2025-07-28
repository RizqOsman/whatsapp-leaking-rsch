#!/bin/bash

IFACE="eth0"

echo "Press Enter and call your target."
read

tshark -i "$IFACE" -l -T fields -e ip.dst -f "udp" \
  -Y "ip.dst!=192.168.0.0/16 and ip.dst!=10.0.0.0/8 and ip.dst!=172.16.0.0/12" | \
while read line; do

    if [[ -z "$line" ]] || [[ "$line" == 224.* || "$line" == 239.* || "$line" == 255.* ]]; then
        continue
    fi

    if grep -Fxq "$line" /tmp/whatsapp_leak_seen; then
        continue
    else
        echo "$line" >> /tmp/whatsapp_leak_seen
    fi
    whois_output=$(whois "$line")
    if echo "$whois_output" | grep -iE "facebook|google" > /dev/null; then
        continue
    fi
    targetinfo=$(echo "$whois_output" | grep -iE "OrgName:|NetName:|Country:")
    echo "=============================="
    echo "$line ---"
    echo "$targetinfo"
    echo "=============================="
done
