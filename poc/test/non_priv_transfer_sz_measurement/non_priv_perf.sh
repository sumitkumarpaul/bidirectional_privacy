#!/bin/bash

declare -a d_file
d_file[0]="../xmlrss/testdata/ds_20.xml"
d_file[1]="../xmlrss/testdata/ds_40.xml"
d_file[2]="../xmlrss/testdata/ds_60.xml"
d_file[3]="../xmlrss/testdata/ds_80.xml"
d_file[4]="../xmlrss/testdata/ds_100.xml"

# Start capturing number of bytes: Input 1: The listening port
Start_net_bytes_cap() {
  local cap_port=$1
  sudo tcpdump -q -i lo dst port $cap_port or src port $cap_port -w "captured_packets_$cap_port.pcap" -U > /dev/null 2>&1&

  local L_TCPDUMP_PID="$!"
  echo "$L_TCPDUMP_PID"

  return $L_TCPDUMP_PID
}

# Stop capturing number of bytes: Input 1: The listening port, Input 2: The PID of already running tcpdump
Stop_net_bytes_cap() {
  local cap_port=$1
  local TCPDUMP_PID=$2
  prev_num_bytes=0
  local num_bytes=1 # Initially changed this way to go enter into the loop
   
  while [ $num_bytes -gt $prev_num_bytes ]
  do
    sleep 10 # Sleep for some time
    du_op=$(du -b "captured_packets_$cap_port.pcap")
    prev_num_bytes=$num_bytes
    #cmd_op=$(echo "$du_op" | grep -oE '[0-9]+')
    num_bytes=$(echo "$du_op" | awk '{print $1}')
  done

  # No more packets are captured, so kill the tcpdump process
  echo "$num_bytes"
  sudo kill -SIGTERM $TCPDUMP_PID
  rm -rf "captured_packets_$cap_port.pcap"

  return $num_bytes
}

non_priv_du_ip="127.0.0.1"
non_priv_du_port="4433"
num_itr=1

Non_priv_perf() {
  for i in 0 1 2 3 4
  do
    for (( j=1; j<=$num_itr; j++ ))
    do
      # Start non-priv server
      #openssl s_server -cert non_priv_du_cert.pem -key non_priv_du_secret_key.pem -accept $non_priv_du_port  & # Put > /dev/null 2>&1 before & to make it silent
      openssl s_server -cert non_priv_du_cert.pem -key non_priv_du_secret_key.pem -accept 4433 &
      TCPDUMP_PID=$(Start_net_bytes_cap $non_priv_du_port)
      sleep 5
      #openssl s_client -connect $non_priv_du_ip:$non_priv_du_port -verify_return_error < ${d_file[$i]}
      #cat ../xmlrss/testdata/ds_1.xml | openssl s_client -connect $non_priv_du_ip:$non_priv_du_port -CAfile non_priv_du_cert.pem -verify_return_error
      cat ${d_file[$i]} | openssl s_client -connect 127.0.0.1:4433 -CAfile non_priv_du_cert.pem -verify_return_error
      sleep 5
      num_bytes=$(Stop_net_bytes_cap $non_priv_du_port $TCPDUMP_PID)
      sleep 5
      sudo killall openssl
    done
    #avg_val=$((total_val / num_itr))
    #avg_val=0
    #echo -e "For ${d_file[$i]}, the amount of network transfer is:\t $num_bytes bytes,\taveage time requirement is:\t $avg_val us" >> $report_file
    echo -e "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo -e "For ${d_file[$i]}, the amount of network transfer is:\t $num_bytes bytes"
  done

  return
}


Non_priv_perf