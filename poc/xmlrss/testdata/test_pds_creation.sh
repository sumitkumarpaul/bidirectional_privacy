#!/bin/bash

if [[ $# < 2 ]]
then
    echo "Enter the number of PD you want to create and the output pc file name:"
    read num_pd
    read output_filename
else
    num_pd=$1
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

echo -e "<?xml version=\"1.0\"?>" >> $output_filename
echo -e "<!DOCTYPE PC SYSTEM \"xmlrss/testdata/pc.dtd\">" >> $output_filename


echo -e '<PC id="pc">' >> $output_filename
echo -e '    <PDS id="pds">' >> $output_filename

for ((i=1; i<=$num_pd; i++))
do
    echo -e "        <PD id=\"pd_$i\">" >> $output_filename

    #Fil-up the statement
    random_statement_str=$(cat /dev/urandom | tr -dc A-Za-z0-9 | head -c "$(shuf -i 500-500 -n 1)")
    echo -e "            <S>$random_statement_str</S>" >> $output_filename

    # openssl x509 -req -in $csr_file -CA $di_cert_file -CAkey $pri_key_file -out $data_cert -extensions v3_req -extfile $data_conf -set_serial 01
    #openssl verify -verbose -CAfile $di_cert_file  $data_cert
    #openssl x509 -inform pem -noout -text -in $data_cert
    # cp $data_conf $base_conf_file

    # Fill-up the code-hash section    
    # Extract the code hash of the same code
    code_sha256=$(sha256sum ../../code_library/code_0/code_0.so)
    code_sha256="${code_sha256:0:64}"
    echo -e "            <CH>$code_sha256</CH>" >> $output_filename

    #Fil-up the auditor's signature section
    $(echo $code_sha256$random_statement_str > ./file.tmp)
    auditor_signature=$(openssl dgst -sha256 -sign ad_secret_key.pem ./file.tmp|openssl base64 -A)
    
    #expr `date +%s%N` / 1000    
    #openssl dgst -verify ad_public_key.pem -sha256 -signature ./sign.tmp ./file.tmp
    #expr `date +%s%N` / 1000

    echo -e "            <AS>$auditor_signature</AS>" >> $output_filename

    echo -e '        </PD>' >> $output_filename
done
    # Only extract the datahash part from the output
    #data_sha256=$(sha256sum ds_$num_di.xml)
    #data_sha256="${data_sha256:0:64}"
    #echo $data_sha256
echo -e '    </PDS>' >> $output_filename
#echo -e "    <DH id=\"dh\">$data_sha256</DH>" >> $output_filename
echo -e "    <DH id=\"dh\"></DH>" >> $output_filename
echo -e "    <SC id=\"sc\"></SC>" >> $output_filename
echo -e "    <VK id=\"vk\"></VK>" >> $output_filename
echo -e '</PC>' >> $output_filename

exit

