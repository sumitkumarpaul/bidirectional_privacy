#!/bin/bash

:'
openssl s_server -quiet -accept $1 -cert ./materials/sample_du_cert.pem -key ./materials/sample_du_pri_key.pem > rcv_data.txt &

echo -e "Started TLS server"

sleep 5

ts_bef_data_access=$(date +%s.%6N)
ts_aft_data_access=$(date +%s.%6N)

echo -e "Timestamp before data access: $ts_bef_data_access and after data access: $ts_aft_data_access"

echo -e "Closing openssl server and client"

killall -TERM openssl
'

cd "./u_data_usage"

./u_data_usage ../../test_data_creater/data_cert/sample_do_data_1_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_10_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_20_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_30_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_40_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_50_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_60_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_70_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_80_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_90_attr.pem
./u_data_usage ../../test_data_creater/data_cert/sample_do_data_100_attr.pem

cd ../
