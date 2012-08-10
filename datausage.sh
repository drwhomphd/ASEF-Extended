#!/bin/bash

cat "$@" |perl -ne 'm/(.*, length )(\d*)/; print "$2\n"' |sort |uniq 

