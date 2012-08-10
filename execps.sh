#!/bin/bash

./adb shell ps >"$@" &
PID=$!
echo $PID
