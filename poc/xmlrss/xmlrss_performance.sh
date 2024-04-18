reset

# ./gradlew build;cp build/libs/xmlrss-1.0-SNAPSHOT.jar .;

cd ../

for num_el in 10 20 30 40 50 60 70 80 90 100
do
    echo -e "\nMeasuring signature performance: $num_el element within PC and redacting: $(($num_el/2)) from them"
    echo -e "==================================================================================================="
    echo -e "Initial signature:"
    java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar Sig xmlrss/testdata/pc_$num_el.xml $num_el pc_signed.xml pubkey.obj
    java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar RSASig xmlrss/testdata/pc_$num_el.xml rsa_signature.bytes rsa_pubkey.obj
    echo -e ""
    echo -e "Verification of the initial signature:"    
    java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar Vf pc_signed.xml pubkey.obj
    java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar RSAVf pc_$num_el.xml rsa_signature.bytes rsa_pubkey.obj
    echo -e ""
    echo -e "Redaction operation:"    
    java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar Red pc_signed.xml $(($num_el/2)) pubkey.obj pc_redacted.xml
    echo -e ""
    echo -e "Verification of the redacted document:"    
    java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar Vf pc_signed.xml pubkey.obj
    java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar RSAVf pc_redacted.xml rsa_signature.bytes rsa_pubkey.obj
done

cd -

exit