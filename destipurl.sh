#!/bin/bash

cat "$@" |perl -ne 'm/(.*? > )(.*?)(\.(\d+|\w+)\: .*)/; print "$2\n"' |sort |uniq

