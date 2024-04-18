#!/bin/bash

if [[ $# < 2 ]]
then
    echo "Enter the number of data points you want to create within the file and the output file name:"
    read num_data_points
    read output_filename
else
    num_data_points=$1
    output_filename=$2
fi


data_conf_folder="./data_conf"
data_output_folder="./data_cert"
org_base_conf_file="sample_do_pri_data_base.conf"
base_conf_file="tmp_sample_do_pri_data_base.conf"
csr_file="sample_do_pri_data.csr"
di_cert_file="sample_di_cert.pem"
pri_key_file="sample_di_pri_key.pem"

# Delete previous data
rm -rf $output_filename
#rm -rf $data_output_folder

#mkdir -p $data_conf_folder
#mkdir -p $data_output_folder

#cp $org_base_conf_file $base_conf_file

echo -e '<D id="d">' >> $output_filename
echo -e '    <DS id="ds">' >> $output_filename

for ((i=1; i<=$num_data_points; i++))
do
    random_int_val=$(((RANDOM<<15|RANDOM)))

    echo -e "        <DI id=\"di_$i\">$random_int_val</DI>" >> $output_filename

    # openssl x509 -req -in $csr_file -CA $di_cert_file -CAkey $pri_key_file -out $data_cert -extensions v3_req -extfile $data_conf -set_serial 01
    #openssl verify -verbose -CAfile $di_cert_file  $data_cert
    #openssl x509 -inform pem -noout -text -in $data_cert
    # cp $data_conf $base_conf_file
done
echo -e '    </DS>' >> $output_filename

# srk=$(openssl dgst -sha256 -sign do_secret_key.pem redkey.obj | openssl base64 -A)
# echo -e "    <SRK>$srk</SRK>" >> $output_filename
echo -e "    <CSK></CSK>" >> $output_filename

echo -e "    <DOS></DOS>" >> $output_filename
# srk=$(cat do_public_key.pem| openssl base64 -A)
#echo -e "    <DOC>$srk</DOC>" >> $output_filename
echo -e "    <DOC></DOC>" >> $output_filename

echo -e '</D>' >> $output_filename

exit

