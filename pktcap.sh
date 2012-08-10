#!/bin/bash

#echo sudo_password | sudo -S tcpdump -i $1 host $2 >"$3" &

tcpdump -i $1 host $2 >"$3" &
PID=$!
echo $PID
