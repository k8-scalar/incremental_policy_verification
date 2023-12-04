#!/bin/bash

IP_LIST=(
    "172.23.1.60"
    "172.23.1.107"
    "172.23.1.69"
    "172.23.1.99"
    "172.23.1.43"
    "172.23.1.22"
    "172.23.1.59"
)
LOG_FILE="ssh_commands.log"
for ip in "${IP_LIST[@]}"; do
    echo "Connecting to $ip"
    
    wt --title Master1 --tabColor "#0066ff" --suppressApplicationTitle ssh -o ProxyJump=r0703236@st.cs.kuleuven.be ubuntu@$ip -t 'sudo systemctl daemon-reload; sudo systemctl restart kubelet; exit'

done