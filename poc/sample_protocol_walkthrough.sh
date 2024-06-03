#!/bin/bash

CP_PORT="4321"
ENC1_PORT="4432"
ENC1_SSL_PORT=`expr $ENC1_PORT + 1`
ENC2_PORT="4498"
ENC2_SSL_PORT=`expr $ENC2_PORT + 1`

do_sk="xmlrss/testdata/do_secret_key.pem"
do_pk="xmlrss/testdata/do_public_key.pem"

declare -a pds_file
DU11_pds_file="xmlrss/testdata/pc_60.xml"
DU21_pds_file="xmlrss/testdata/pc_20.xml"
DO_pds_file="xmlrss/testdata/pc_40.xml"

declare -a d_file
d_file[0]="xmlrss/testdata/ds_100.xml"
def_d_file=${d_file[0]}

# Run sample walkthorugh of the protocol
Sample_walkthrough() {
  # Ensure that the involved parties are not running at the moment
  sudo killall code_provider > /dev/null 2>&1
  sudo killall data_owner > /dev/null 2>&1
  rm -rf ./DU_storage/$ENC1_SSL_PORT
  rm -rf ./DU_storage/$ENC2_SSL_PORT
  rm -rf ./enc/$ENC1_SSL_PORT
  rm -rf ./enc/$ENC2_SSL_PORT

  if [ "$non_sgx" = "y" ]; then
    sudo killall enclave > /dev/null 2>&1
  else
    sudo killall gramine-sgx > /dev/null 2>&1
  fi

  ##########################
  # Start code provider
  ##########################

  # Run CP in demon mode and save its PID
  if [ "$non_sgx" = "y" ]; then
    ./code_provider $CP_PORT non-sgx&
  else
    ./code_provider $CP_PORT sgx&
  fi
  
  CP_PID="$!"


  ##########################
  # DU[1,1] performs Setup
  ##########################

  # Setup DU[1,1], it proposes 60 data processing statements
  cp $DU11_pds_file pds.xml

  if [ "$non_sgx" = "y" ]; then
    ./enclave $ENC1_PORT non-sgx &
  else
    gramine-sgx ./enclave $ENC1_PORT sgx &
  fi

  E1_PID="$!"
  # Connect with DU[1,1]'s enclave using descriptor 3
  sleep 5
  exec 3<>/dev/tcp/127.0.0.1/$ENC1_PORT

  # Initialize the DU[1,1]'s enclave
  echo "Init" >&3
  read -u 3 enc_message
  if [ "$enc_message" != "OK" ]; then
    echo "Initialization of DU's enclave returned error..!!"
    echo "Received message from DU's enclave after initialization: $enc_message"
  fi

  ####################################
  # Similarly, DU[2,1] performs Setup
  ####################################

  # Setup DU[2,1], it proposes 20 data processing statements
  cp $DU21_pds_file pds.xml

  if [ "$non_sgx" = "y" ]; then
    ./enclave $ENC2_PORT non-sgx &
  else
    gramine-sgx ./enclave $ENC2_PORT sgx &
  fi

  E2_PID="$!"
  # Connect with DU[2,1]'s enclave using descriptor 4
  sleep 5
  exec 4<>/dev/tcp/127.0.0.1/$ENC2_PORT

  # Initialize the DU[2,1]'s enclave
  echo "Init" >&4
  read -u 4 enc_message
  if [ "$enc_message" != "OK" ]; then
    echo "Initialization of DU's enclave returned error..!!"
    echo "Received message from DU's enclave after initialization: $enc_message"
  fi

  #############################
  # DO SendOrigData to DU[1,1]
  #############################
  # Set DU[1,1]'s enclave in data receiving mode
  echo "SaveData" >&3

  # DO agrees with 40 out of 60 proposed data-processing statements
  if [ "$non_sgx" = "y" ]; then
    ./data_owner $def_d_file $DO_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT non-sgx
  else
    ./data_owner $def_d_file $DO_pds_file $do_sk $do_pk 127.0.0.1 $ENC1_SSL_PORT sgx
  fi
    
  read -u 3 enc_message
  if [ "$enc_message" == *"Not-OK"* ]; then
    echo "SaveData returned error..!!"
    echo "Received message from the enclave during saving data: $enc_message"
  fi

  #############################
  # Data processing in DU[1,1]
  #############################
  # Instruct the enclave to perform the processing for statement 0 (Vector inner product) on did:0
  echo "Process,0,0" >&3

  read -u 3 enc_message

  # Is the enclave enclave says OK?
  if [ "$enc_message" == *"Not-OK"* ]; then
    echo "Process returned error..!!"
    echo "Received message from the enclave during Process data: $enc_message"
  fi
    
  time_in_us=`cat DU_storage/$ENC1_SSL_PORT/enc_perf.log`
    
  #echo -e "For processing (vector inner product) data by DU[1,1], time requirement is:\t $time_in_us us"

  ##########################
  # Data forwarding
  ##########################
  # Put the DU[2,1]'s enclave in savedata mode
  echo "SaveData" >&4
      
  # Give some time to the DU[2,1]'s enclave to stabalize
  sleep 1

  # Instruct DU[1,1]'s enclave to forward the data with 20 out of 40 agreed elements redaction
  echo "PrepFrd,127.0.0.1,$ENC2_SSL_PORT,0,[0:19]" >&3

  read -u 4 enc_message

  # Is DU[2,1]'s enclave says OK?
  if [ "$enc_message" == *"Not-OK"* ]; then
    echo "SaveData returned error..!!"
    echo "Received message from the enclave during saving data: $enc_message"
  fi
  
  #############################
  # Data processing in DU[2,1]
  #############################
  # Instruct the enclave to perform the processing for statement 1 (Summation of all the elements) on did:0
  echo "Process,0,1" >&4

  read -u 3 enc_message

  # Is the enclave enclave says OK?
  if [ "$enc_message" == *"Not-OK"* ]; then
    echo "Process returned error..!!"
    echo "Received message from the enclave during Process data: $enc_message"
  fi
    
  time_in_us=`cat DU_storage/$ENC2_SSL_PORT/enc_perf.log`
    
  #echo -e "For processing (Summation of all the elements) data by DU[2,1], time requirement is:\t $time_in_us us"

  # Finalize the DU[2,1]'s enclave and close the connection
  echo "Finalize" >&4
  sleep 1
  exec 4<&-

  # Finalize the DU[1,1]'s enclave and close the connection
  echo "Finalize" >&3
  sleep 1
  exec 3<&-

  # Close the CP
  kill -SIGTERM $CP_PID
  
  return
}


if [[ $# < 1 ]]
then
    read -p 'Do you have support of SGX in your system? [y / (N)] ' sgx_support
else
    sgx_support=$1
fi

echo -e "============================================================================================================"
echo -e "Running through all the operations of the protocol"

if [ "$sgx_support" = "y" ]; then
  non_sgx="N"
else
  non_sgx="y"
  echo -e "Note: The walkthorugh of the protocol is captured in non-sgx mode only"
fi

echo -e "============================================================================================================"

#Setup_perf
#SndOrgData_perf
#ProcessData_perf
#ForwardData_perf
Sample_walkthrough

exit