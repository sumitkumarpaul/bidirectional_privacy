#!/bin/bash
# Delete previous data
rm -rf *.xml
rm -rf *.pem
rm -rf *xml.obj

$(./ad_credential_creator.sh)
$(./do_credential_creator.sh)

$(./test_d_creation.sh 1 ds_1.xml)
$(./test_d_creation.sh 10 ds_10.xml)
$(./test_d_creation.sh 100 ds_100.xml)
$(./test_d_creation.sh 1000 ds_1000.xml)
$(./test_d_creation.sh 10000 ds_10000.xml)

$(./test_pds_creation.sh 1 pc_1.xml)
$(./test_pds_creation.sh 10 pc_10.xml)
$(./test_pds_creation.sh 20 pc_20.xml)
$(./test_pds_creation.sh 30 pc_30.xml)
$(./test_pds_creation.sh 40 pc_40.xml)
$(./test_pds_creation.sh 50 pc_50.xml)
$(./test_pds_creation.sh 60 pc_60.xml)
$(./test_pds_creation.sh 70 pc_720.xml)
$(./test_pds_creation.sh 80 pc_80.xml)
$(./test_pds_creation.sh 90 pc_90.xml)
$(./test_pds_creation.sh 100 pc_100.xml)

rm -rf *tmp

exit

