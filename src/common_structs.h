#ifndef __COMMON_STRUCTS_H
#define __COMMON_STRUCTS_H

#include <stdbool.h>

/* This struct defines the anonymization parameters */
typedef struct anonymization_config {
    bool anonymize_multicast_broadcast; 
    bool anonymize_srcmac_oui; 
    bool anonymize_srcmac_id; 
    bool anonymize_dstmac_oui; 
    bool anonymize_dstmac_id; 
    bool preserve_prefix; 
    bool anonymize_mac_in_arphdr; 
    bool anonymize_ipv4_in_arphdr; 
    __u32 src_ip_mask_lengths; 
    __u32 dest_ip_mask_lengths; 
    __u32 random_salt; 
} anonymization_config;

typedef struct ip_mask {
    __u32 mask; 
    __u32 len; 
    bool is_src_mask; 
} ip_mask; 

#endif