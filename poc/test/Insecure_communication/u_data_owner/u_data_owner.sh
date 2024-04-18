#!/bin/bash

ts_bef=$(date +%s%N)
#openssl s_client -quiet -no_ign_eof -connect $1:$2 < $3
openssl s_time -connect $1:$2 < $3 
ts_aft=$(date +%s%N)

ts_diff=$(($ts_aft - $ts_bef))
ts_diff=`expr $ts_diff / 1000`
ts_bef=`expr $ts_bef / 1000`
ts_aft=`expr $ts_aft / 1000`

echo -e "Before-timestamp: $ts_bef us, after-timestamp: $ts_aft us, time difference: $ts_diff us"
