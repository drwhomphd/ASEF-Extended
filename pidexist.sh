#!/bin/bash
ps -a |grep $1 |grep -v grep |grep -v pidexist
