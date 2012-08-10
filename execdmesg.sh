#!/bin/bash

./adb shell dmesg >"$@" &
PID=$!
echo $PID
