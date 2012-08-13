#!/bin/bash

adb shell dumpsys >"$@" &
PID=$!
echo $PID
