#!/bin/bash
CP_PORT="4321"
ENC1_PORT="4432"
ENC1_SSL_PORT=`expr $ENC1_PORT + 1`
ENC2_PORT="4498"
ENC2_SSL_PORT=`expr $ENC2_PORT + 1`

do_sk="xmlrss/testdata/do_secret_key.pem"
do_pk="xmlrss/testdata/do_public_key.pem"

declare -a pds_file
pds_file[0]="xmlrss/testdata/pc_20.xml"
pds_file[1]="xmlrss/testdata/pc_40.xml"
pds_file[2]="xmlrss/testdata/pc_60.xml"
pds_file[3]="xmlrss/testdata/pc_80.xml"
pds_file[4]="xmlrss/testdata/pc_100.xml"
def_pds_file="xmlrss/testdata/pc_1.xml"

declare -a d_file
#d_file[0]="xmlrss/testdata/ds_1.xml"
#d_file[1]="xmlrss/testdata/ds_10.xml"
#d_file[2]="xmlrss/testdata/ds_100.xml"
#d_file[3]="xmlrss/testdata/ds_1000.xml"
#d_file[4]="xmlrss/testdata/ds_10000.xml"
d_file[0]="xmlrss/testdata/ds_20.xml"
d_file[1]="xmlrss/testdata/ds_40.xml"
d_file[2]="xmlrss/testdata/ds_60.xml"
d_file[3]="xmlrss/testdata/ds_80.xml"
d_file[4]="xmlrss/testdata/ds_100.xml"
def_d_file="xmlrss/testdata/ds_1.xml"

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

# Run setup experiments
Setup_perf() {
  # Ensure that the involved parties are not running at the moment
  sudo killall code_provider > /dev/null 2>&1

  if [ "$non_priv" = "y" ]; then
    sudo killall enclave > /dev/null 2>&1
  else
    sudo killall gramine-sgx > /dev/null 2>&1
  fi

  # Run CP in demon mode and save its PID
  if [ "$non_priv" = "y" ]; then
    ./code_provider $CP_PORT non-sgx&
  else
    ./code_provider $CP_PORT sgx&
  fi

  CP_PID="$!"

  raw_log_filename="$log_folder/Setup_vary_#PD.csv"

  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename
  echo -e "\n------------------------------" >> $report_file
  echo -e "Overview of the Setup stage" >> $report_file
  echo -e "------------------------------" >> $report_file

  for i in "${!pds_file[@]}"
  do
    cp ${pds_file[$i]} pds.xml

    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC1_SSL_PORT)
      fi
      
      if [ "$non_priv" = "y" ]; then
        ./enclave $ENC1_PORT non-sgx  > /dev/null 2>&1&
      else
        gramine-sgx ./enclave $ENC1_PORT sgx  > /dev/null 2>&1&
      fi
      
      E1_PID="$!"
      # Connect with enclave_1
      sleep 5
      exec 3<>/dev/tcp/127.0.0.1/$ENC1_PORT

      # Initialize enclave_1
      echo "Init" >&3
      read -u 3 enc_message
      if [ "$enc_message" != "OK" ]; then
        echo "Initialization of the first enclave returned error..!!"
        echo "Received message from the enclave after initialization: $enc_message"
      fi
      time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
      echo "Finalize" >&3

      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC1_SSL_PORT $TCPDUMP_PID)
      else 
        echo "Init, ${pds_file[$i]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi
      
      sleep 1
      exec 3<&-
      sleep 2
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${pds_file[$i]}, the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  # Close the CP
  kill -SIGKILL $CP_PID
  
  return
}

# Run original data sending experiments
SndOrgData_perf() {
  # Ensure that the involved parties are not running at the moment
  sudo killall code_provider > /dev/null 2>&1
  sudo killall data_owner > /dev/null 2>&1

  if [ "$non_priv" = "y" ]; then
    sudo killall enclave > /dev/null 2>&1
  else
    sudo killall gramine-sgx > /dev/null 2>&1
  fi

  # Run CP in demon mode and save its PID
  if [ "$non_priv" = "y" ]; then
    ./code_provider $CP_PORT non-sgx&
  else
    ./code_provider $CP_PORT sgx&
  fi
  
  CP_PID="$!"

  # Setup the enclave first, use #PD = 100
  cp ${pds_file[4]} pds.xml

  if [ "$non_priv" = "y" ]; then
    ./enclave $ENC1_PORT non-sgx  > /dev/null 2>&1&
  else
    gramine-sgx ./enclave $ENC1_PORT sgx > /dev/null 2>&1&
  fi
  
  E1_PID="$!"
  # Connect with enclave_1
  sleep 5
  exec 3<>/dev/tcp/127.0.0.1/$ENC1_PORT

  # Initialize enclave_1
  echo "Init" >&3
  read -u 3 enc_message
  if [ "$enc_message" != "OK" ]; then
    echo "Initialization of the first enclave returned error..!!"
    echo "Received message from the enclave after initialization: $enc_message"
  fi
  
  raw_log_filename="$log_folder/SndOrgData_vary_#PD.csv"
  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename
  echo -e "\n------------------------------" >> $report_file  
  echo -e "Overview of the SendOrg stage" >> $report_file
  echo -e "------------------------------" >> $report_file
  echo -e "\nVary #PD" >> $report_file
  echo -e "++++++++++" >> $report_file
  # Keep #DI = 100, but vary #PD
  for i in "${!pds_file[@]}"
  do
    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC1_SSL_PORT)
      fi
      echo "SaveData" >&3
  
      # Give some time to the receiving enclave to stabalize
      sleep 1
  
      if [ "$non_priv" = "y" ]; then
        ./data_owner $def_d_file ${pds_file[$i]} $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT non-sgx
      else
        ./data_owner $def_d_file ${pds_file[$i]} $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT sgx
      fi
      
      read -u 3 enc_message
      if [ "$enc_message" == *"Not-OK"* ]; then
        echo "SaveData returned error..!!"
        echo "Received message from the enclave during saving data: $enc_message"
      fi
      time_in_us=`cat ./do_perf.log`
      #time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
  
      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC1_SSL_PORT $TCPDUMP_PID)
      else 
        echo "SendOrgData, ${pds_file[$i]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi
      sleep 1
      rm "./do_perf.log"
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${pds_file[$i]}, the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  raw_log_filename="$log_folder/SndOrgData_vary_#DI.csv"
  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename

  echo -e "\nVary #DI" >> $report_file
  echo -e "++++++++++" >> $report_file
  # Vary #DI, but keep #PD = 20
  for i in "${!d_file[@]}"
  do
    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC1_SSL_PORT)
      fi
      echo "SaveData" >&3

      # Give some time to the receiving enclave to stabalize
      sleep 1

      if [ "$non_priv" = "y" ]; then
        ./data_owner ${d_file[$i]} $def_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT non-sgx
      else
        ./data_owner ${d_file[$i]} $def_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT sgx
      fi
      
      read -u 3 enc_message
      if [ "$enc_message" == *"Not-OK"* ]; then
        echo "SaveData returned error..!!"
        echo "Received message from the enclave during saving data: $enc_message"
      fi
      time_in_us=`cat ./do_perf.log`
      #time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
      
      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC1_SSL_PORT $TCPDUMP_PID)
      else
        echo "SendOrgData, ${d_file[$i]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi
      sleep 1
      rm "./do_perf.log"
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${d_file[$i]}, the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  # Finalize the enclave and close the connection
  echo "Finalize" >&3
  sleep 1
  exec 3<&-

  # Close the CP
  kill -SIGKILL $CP_PID
  
  return
}

# Run data-forwarding experiments
ForwardData_perf() {
  # Ensure that the involved parties are not running at the moment
  sudo killall code_provider > /dev/null 2>&1
  sudo killall data_owner > /dev/null 2>&1

  if [ "$non_priv" = "y" ]; then
    sudo killall enclave > /dev/null 2>&1
  else
    sudo killall gramine-sgx > /dev/null 2>&1
  fi
  
  # Run CP in demon mode and save its PID
  if [ "$non_priv" = "y" ]; then
    ./code_provider $CP_PORT non-sgx&
  else
    ./code_provider $CP_PORT sgx&
  fi
  
  CP_PID="$!"

  # Setup the sending enclave first, use #PD = 100
  cp ${pds_file[4]} pds.xml

  if [ "$non_priv" = "y" ]; then
    ./enclave $ENC1_PORT non-sgx > /dev/null 2>&1&
  else
    gramine-sgx ./enclave $ENC1_PORT sgx  > /dev/null 2>&1&
  fi
  
  E1_PID="$!"
  # Connect with sending enclave using descriptor 3
  sleep 5
  exec 3<>/dev/tcp/127.0.0.1/$ENC1_PORT

  # Initialize sending enclave
  echo "Init" >&3
  read -u 3 enc_message
  if [ "$enc_message" != "OK" ]; then
    echo "Initialization of the sending enclave returned error..!!"
    echo "Received message from the enclave after initialization: $enc_message"
  fi

  # Pre-install some data into the sending enclave
  # did [0-> #DI:100, #PD:20][1-> #DI:100, #PD:40][2-> #DI:100, #PD:60][3-> #DI:100, #PD:80][4-> #DI:100, #PD:100]
  for i in "${!pds_file[@]}"
  do
    echo "SaveData" >&3
    
    # Give some time to the receiving enclave to stabalize
    sleep 1
    
    if [ "$non_priv" = "y" ]; then
      ./data_owner $def_d_file ${pds_file[$i]} $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT non-sgx
    else
      ./data_owner $def_d_file ${pds_file[$i]} $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT sgx
    fi
    
    read -u 3 enc_message
    if [ "$enc_message" == *"Not-OK"* ]; then
      echo "SaveData returned error..!!"
      echo "Received message from the enclave during saving data: $enc_message"
    fi
  done

  # did [5-> #DI:1, #PD:20][6-> #DI:10, #PD:20][7-> #DI:100, #PD:20][8-> #DI:1000, #PD:20][9-> #DI:10000, #PD:20]
  for i in "${!d_file[@]}"
  do
    echo "SaveData" >&3
    
    # Give some time to the receiving enclave to stabalize
    sleep 1

    if [ "$non_priv" = "y" ]; then
      ./data_owner ${d_file[$i]} $def_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT non-sgx
    else
      ./data_owner ${d_file[$i]} $def_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT
    fi
    
    read -u 3 enc_message
    if [ "$enc_message" == *"Not-OK"* ]; then
      echo "SaveData returned error..!!"
      echo "Received message from the enclave during saving data: $enc_message"
    fi
  done

  # Setup the receiving enclave, use #PD = 100
  cp ${pds_file[4]} pds.xml

  if [ "$non_priv" = "y" ]; then
    ./enclave $ENC2_PORT non-sgx > /dev/null 2>&1&
  else
    gramine-sgx ./enclave $ENC2_PORT sgx > /dev/null 2>&1&
  fi

  E1_PID="$!"
  # Connect with receiving enclave using descriptor 4
  sleep 5
  exec 4<>/dev/tcp/127.0.0.1/$ENC2_PORT

  # Initialize receiving enclave
  echo "Init" >&4
  read -u 4 enc_message
  if [ "$enc_message" != "OK" ]; then
    echo "Initialization of the receiving enclave returned error..!!"
    echo "Received message from the enclave after initialization: $enc_message"
  fi

  ################################
  # Actual forwarding test
  ################################
  # Keep #DI fixed, but vary #PD, no-redaction
  raw_log_filename="$log_folder/ForwardData_vary_#PD_0%_redact.csv"
  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename
  echo -e "\n---------------------------------" >> $report_file
  echo -e "Overview of the ForwardData stage" >> $report_file
  echo -e "---------------------------------" >> $report_file
  echo -e "\nVary #PD but no redaction" >> $report_file
  echo -e "+++++++++++++++++++++++++++" >> $report_file

  # did [0-> #DI:100, #PD:20][1-> #DI:100, #PD:40][2-> #DI:100, #PD:60][3-> #DI:100, #PD:80][4-> #DI:100, #PD:100]
  for i in 0 1 2 3 4
  do
    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC2_SSL_PORT)
      fi
      # Put the receiving enclave in savedata mode
      echo "SaveData" >&4
      
      # Give some time to the receiving enclave to stabalize
      sleep 1

      # Instruct sending enclave to forward the data without redaction
      echo "PrepFrd,127.0.0.1,$ENC2_SSL_PORT,$i,[0:0]" >&3

      read -u 4 enc_message

      # Is receiving enclave says OK?
      if [ "$enc_message" == *"Not-OK"* ]; then
        echo "SaveData returned error..!!"
        echo "Received message from the enclave during saving data: $enc_message"
      fi
      time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC2_SSL_PORT $TCPDUMP_PID)
      else 
        echo "Forward(vary #PD)[0%-redaction], ${pds_file[$i]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi      
      sleep 1
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${pds_file[$i]}[0%-redaction], the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  # Keep #DI fixed, but vary #PD, 25%-redaction
  raw_log_filename="$log_folder/ForwardData_vary_#PD_25%_redact.csv"
  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename
  echo -e "\nVary #PD and 25% redaction" >> $report_file
  echo -e "++++++++++++++++++++++++++++++" >> $report_file

  # did [0-> #DI:100, #PD:20][1-> #DI:100, #PD:40][2-> #DI:100, #PD:60][3-> #DI:100, #PD:80][4-> #DI:100, #PD:100]
  for i in 0 1 2 3 4
  do
    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC2_SSL_PORT)
      fi
      # Put the receiving enclave in savedata mode
      echo "SaveData" >&4
      
      # Give some time to the receiving enclave to stabalize
      sleep 1
      
      #Determine upto which it should be redacted
      end_red=$(((25 * ($i + 1) * 20) / 100))

      # Instruct sending enclave to forward the data with redaction
      echo "PrepFrd,127.0.0.1,$ENC2_SSL_PORT,$i,[1:$end_red]" >&3

      read -u 4 enc_message

      # Is receiving enclave says OK?
      if [ "$enc_message" == *"Not-OK"* ]; then
        echo "SaveData returned error..!!"
        echo "Received message from the enclave during saving data: $enc_message"
      fi
      time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC2_SSL_PORT $TCPDUMP_PID)
      else 
        echo "Forward(vary #PD)[25%-redaction], ${pds_file[$i]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi
      sleep 1
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${pds_file[$i]}[25%-redaction], the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  # Keep #DI fixed, but vary #PD, 50%-redaction
  raw_log_filename="$log_folder/ForwardData_vary_#PD_50%_redact.csv"
  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename
  echo -e "\nVary #PD and 50% redaction" >> $report_file
  echo -e "++++++++++++++++++++++++++++++" >> $report_file

  # did [0-> #DI:100, #PD:20][1-> #DI:100, #PD:40][2-> #DI:100, #PD:60][3-> #DI:100, #PD:80][4-> #DI:100, #PD:100]
  for i in 0 1 2 3 4
  do
    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC2_SSL_PORT)
      fi
      # Put the receiving enclave in savedata mode
      echo "SaveData" >&4
      
      # Give some time to the receiving enclave to stabalize
      sleep 1

      #Determine upto which it should be redacted
      end_red=$(((50 * ($i + 1) * 20) / 100))

      # Instruct sending enclave to forward the data with redaction
      echo "PrepFrd,127.0.0.1,$ENC2_SSL_PORT,$i,[1:$end_red]" >&3

      read -u 4 enc_message

      # Is receiving enclave says OK?
      if [ "$enc_message" == *"Not-OK"* ]; then
        echo "SaveData returned error..!!"
        echo "Received message from the enclave during saving data: $enc_message"
      fi
      time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`

      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC2_SSL_PORT $TCPDUMP_PID)
      else 
        echo "Forward(vary #PD)[50%-redaction], ${pds_file[$i]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi
      sleep 1
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${pds_file[$i]}[50%-redaction], the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  # Vary #DI, but keep #PD fixed
  raw_log_filename="$log_folder/ForwardData_vary_#DI.csv"
  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename
  echo -e "\nVary #DI " >> $report_file
  echo -e "+++++++++++" >> $report_file

  # did [5-> #DI:1, #PD:20][6-> #DI:10, #PD:20][7-> #DI:100, #PD:20][8-> #DI:1000, #PD:20][9-> #DI:10000, #PD:20]
  for i in 5 6 7 8 9
  do
    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC2_SSL_PORT)
      fi    
      # Put the receiving enclave in savedata mode
      echo "SaveData" >&4
      
      # Give some time to the receiving enclave to stabalize
      sleep 1

      # Instruct sending enclave to forward the data without redaction
      echo "PrepFrd,127.0.0.1,$ENC2_SSL_PORT,$i,[0:0]" >&3

      read -u 4 enc_message

      # Is receiving enclave says OK?
      if [ "$enc_message" == *"Not-OK"* ]; then
        echo "SaveData returned error..!!"
        echo "Received message from the enclave during saving data: $enc_message"
      fi
      time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
      array_el=$(($i - 5))
      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC2_SSL_PORT $TCPDUMP_PID)
      else 
        echo "Forward(vary #DI), ${d_file[$array_el]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi      
      sleep 1
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${d_file[$array_el]}, the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  # Finalize the receiving enclave and close the connection
  echo "Finalize" >&4
  sleep 1
  exec 4<&-

  # Finalize the sending enclave and close the connection
  echo "Finalize" >&3
  sleep 1
  exec 3<&-

  # Close the CP
  kill -SIGKILL $CP_PID
  
  return
}

# Run data-processing experiments
ProcessData_perf() {
  # Ensure that the involved parties are not running at the moment
  sudo killall code_provider > /dev/null 2>&1
  sudo killall data_owner > /dev/null 2>&1

  if [ "$non_priv" = "y" ]; then
    sudo killall enclave > /dev/null 2>&1
  else
    sudo killall gramine-sgx > /dev/null 2>&1
  fi

  # Run CP in demon mode and save its PID
  if [ "$non_priv" = "y" ]; then
    ./code_provider $CP_PORT non-sgx&
  else
    ./code_provider $CP_PORT sgx&
  fi
  
  CP_PID="$!"

  # Setup the sending enclave first, use #PD = 100
  cp ${pds_file[4]} pds.xml

  if [ "$non_priv" = "y" ]; then
    ./enclave $ENC1_PORT non-sgx > /dev/null 2>&1&
  else
    gramine-sgx ./enclave $ENC1_PORT sgx  > /dev/null 2>&1&
  fi

  E1_PID="$!"
  # Connect with sending enclave using descriptor 3
  sleep 5
  exec 3<>/dev/tcp/127.0.0.1/$ENC1_PORT

  # Initialize the DU's enclave
  echo "Init" >&3
  read -u 3 enc_message
  if [ "$enc_message" != "OK" ]; then
    echo "Initialization of DU's enclave returned error..!!"
    echo "Received message from DU's enclave after initialization: $enc_message"
  fi

  # Pre-install some data into the DU's enclave
  # did [0-> #DI:100, #PD:20][1-> #DI:100, #PD:40][2-> #DI:100, #PD:60][3-> #DI:100, #PD:80][4-> #DI:100, #PD:100]
  for i in "${!d_file[@]}"
  do
    echo "SaveData" >&3
    
    # Give some time to the receiving enclave to stabalize
    sleep 1

    if [ "$non_priv" = "y" ]; then
      ./data_owner ${d_file[$i]} $def_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT non-sgx
    else
      ./data_owner ${d_file[$i]} $def_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT sgx
    fi
    
    read -u 3 enc_message
    if [ "$enc_message" == *"Not-OK"* ]; then
      echo "SaveData returned error..!!"
      echo "Received message from the enclave during saving data: $enc_message"
    fi
  done

  # Vary #DI, but keep #PD fixed
  raw_log_filename="$log_folder/ProcessData_vary_#DI.csv"
  echo "Operation, Configuration, Iteration number, Time in us" >> $raw_log_filename
  echo -e "\n------------------------------" >> $report_file
  echo -e "Overview of the Process stage" >> $report_file
  echo -e "------------------------------" >> $report_file  
  echo -e "\nVary #DI " >> $report_file
  echo -e "+++++++++++" >> $report_file

  ##########################
  # Actual processing test
  ##########################

  for i in 0 1 2 3 4
  do
    for (( j=0; j<=$num_itr; j++ ))
    do
      # For the first measurement only
      if [ $j -eq 0 ]; then
        total_val=0
        TCPDUMP_PID=0
        # Start tcpdump
        TCPDUMP_PID=$(Start_net_bytes_cap $ENC1_SSL_PORT)
      fi 
      # Instruct the enclave to perform the processing, always for the first statement(each statement is same)
      echo "Process,$i,0" >&3

      read -u 3 enc_message

      # Is the enclave enclave says OK?
      if [ "$enc_message" == *"Not-OK"* ]; then
        echo "Process returned error..!!"
        echo "Received message from the enclave during Process data: $enc_message"
      fi
      time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
      # Do not log the first experiment result, it is only for measruing the network traffic
      if [ $j -eq 0 ]; then
        # Calculate the number of bytes transferred
        num_bytes=$(Stop_net_bytes_cap $ENC1_SSL_PORT $TCPDUMP_PID)
      else 
        echo "Process, ${d_file[$i]}, $j, $time_in_us" >> $raw_log_filename
        ((total_val += time_in_us))
      fi      
      sleep 1
    done
    avg_val=$((total_val / num_itr))
    echo -e "For ${d_file[$i]}, the amount of network transfer is:\t $num_bytes bytes,\taverage time requirement is:\t $avg_val us" >> $report_file
  done

  # Finalize the DU's enclave and close the connection
  echo "Finalize" >&3
  sleep 1
  exec 3<&-

  # Close the CP
  kill -SIGKILL $CP_PID
  
  return
}

if [[ $# < 2 ]]
then
    read -p 'Number of iterations for each experiment: ' num_itr
    read -p 'Want to measure performance of non-private mode? [y / (N)] ' non_priv
else
    num_itr=$1
    non_priv=$2
fi

# Install tcpdump, which will be required for measuring the network transfer
sudo apt-get install -y tcpdump

non_priv="${non_priv,,}"
log_timestamp="$(date +"%d_%m_%Y_%H-%M-%S")"
log_folder="Perf_log_$log_timestamp/"
mkdir $log_folder
report_file="$log_folder/Overall_report.txt"

echo -e "============================================================================================================"
echo -e "Started performance measurement of BPPM"
echo -e "Please wait, it will take considerable amount of time..."
echo -e "============================================================================================================" >> $report_file
echo -e "Measured average BPPM performance parameters of after running each combinations for: $num_itr-times" >> $report_file

if [ "$non_priv" = "y" ]; then
  echo -e "Note: The performance is measured for non-private mode only" >> $report_file
fi

echo -e "============================================================================================================" >> $report_file

Setup_perf
SndOrgData_perf
ProcessData_perf
ForwardData_perf

echo -e "\nPerformance measurement completed..!! Open the folder $log_folder for detailed reports."
echo -e "============================================================================================================"


exit