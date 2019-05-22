#ifndef __create_root_ca_in_c_constants__
#define __create_root_ca_in_c_constants__

#define     ROOT_KEY_FILE       "mozroot.key"
#define     ROOT_KEY_PASS       "moez"
#define     CERT_OUTPUT_FILE    "mozrootca.crt"
#define     START_DATE_ASN1     "20190101000000Z"
#define     END_DATE_ASN1       "20290101000000Z"
#define     SERIAL              (0x7000000000000001)
#define     SUBJECT_LINE        "/C=IR/ST=Tehran/L=Tehran/O=Moez Home/OU=Security Department/CN=moezhome.ir/emailAddress=a_moezz@moezhome.ir"
#define     OUTPUT_X509_V3      (false)
#define     LOAD_ECENGINE       (true)
#define     ECENGINE_LOCATION   ("/tmp/ecengine.so")

typedef     char    bool;
#define     true            1
#define     false           0
#define     NULL            0

#endif
