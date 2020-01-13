
#define MAX_STAGE_COUNT 4
#define MAX_PORTS 511
#define MAX_INDEX_INT 4294967295
#define BIT16_INDEX 65535
#define MAX_INDEX_TEST 2147483647

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  port_t;
typedef bit<16> l4_port_t;

typedef bit<16>  index_t;
typedef bit<16>  half_ipAddr_t;

typedef bit<80> reg_key;
typedef bit<16> id_t;
typedef bit<4> pk_stage_t;



const bit<8> TYPE_ICMP = 0x01;
const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> TYPE_TCP  = 0x06;
const bit<8> TYPE_UDP  = 0x11;
const bit<6> SYN = 2;
const bit<4> BYTE_TO_BIT = 8;
const bit<9> CPU_PORT = 255;
