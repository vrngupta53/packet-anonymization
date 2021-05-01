#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../headers/jhash.h"

#include "common_structs.h"

#define MAX_IP_MASKS 2048

#define MAX_LEN 50

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); 
    __type(value, anonymization_config); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps"); 

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_MASKS);
    __type(key, ip_mask); 
    __type(value, bool); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_masks_map SEC(".maps"); 


struct hdr_cursor {
    void *pos; 
}; 

static __always_inline void assign_hash(unsigned char* arr, u32 hash) {
    arr[0] = (hash >> 24) & 0xFF; 
    arr[1] = (hash >> 16) & 0xFF; 
    arr[2] = (hash >> 8) & 0xFF; 
}

static __always_inline int anonymize_ethhdr(struct hdr_cursor *nh, void *data_end, anonymization_config *config) {
    struct ethhdr *eth = nh->pos; 
    int hdrsize = sizeof(*eth); 

    if(nh->pos + hdrsize > data_end) return -1; 
    
    if(config->anonymize_srcmac_oui) {
       u32 hash = jhash(eth->h_source, 3, config->random_salt); 
       assign_hash(eth->h_source, hash); 
    }
    if(config->anonymize_dstmac_oui) {
       u32 hash = jhash(eth->h_dest, 3, config->random_salt); 
       assign_hash(eth->h_dest, hash);
    }
    if(config->anonymize_srcmac_id) {
       u32 hash = jhash(eth->h_source + 3, 3, config->random_salt); 
       assign_hash(eth->h_source + 3, hash);
    }
    if(config->anonymize_dstmac_id) {
       u32 hash = jhash(eth->h_dest + 3, 3, config->random_salt); 
       assign_hash(eth->h_dest, hash);
    }

    nh->pos += hdrsize; 
    return eth->h_proto; 
}

static __always_inline int anonymize_iphdr(struct hdr_cursor *nh, void *data_end, anonymization_config *config) {
    struct iphdr *iph = nh->pos; 
    int hdrsize; 

    if(iph + 1 > data_end) return -1; 

    hdrsize = iph->ihl * 4; 
    if(hdrsize < sizeof(*iph)) return -1; 

    if(nh->pos + hdrsize > data_end) return -1; 


    if(config->preserve_prefix) {
        u32 saddr = bpf_ntohl(iph->saddr);
        u32 daddr = bpf_ntohl(iph->daddr); 

        ip_mask mask_candidate = {0}; 

        //check for source ip
        for(int mask_length = 32; mask_length > 0; mask_length--) {
            mask_candidate.mask = saddr & (0xFFFFFFFF << (32 - mask_length));        //extract top mask_length bits from ip
            mask_candidate.len = mask_length; 
            mask_candidate.is_src_mask = true; 

            if(bpf_map_lookup_elem(&ip_masks_map, &mask_candidate) != NULL) {
                u32 to_hash = saddr & ((1 << (32 - mask_length)) - 1);                  //extract bottom 32 - mask_length bits from ip
                u32 hash = jhash_2words(to_hash, mask_length, config->random_salt);     //hash the bottom bits
                saddr = mask_candidate.mask + (hash >> mask_length);                 //assign the top 32-mask_length hashed bits
                break;  
            }
        }

        //check for destination ip 
        for(int mask_length = 32; mask_length > 0; mask_length--) {
            mask_candidate.mask = daddr & (0xFFFFFFFF << (32 - mask_length));        //extract top mask_length bits from ip
            mask_candidate.len = mask_length; 
            mask_candidate.is_src_mask = false; 

            if(bpf_map_lookup_elem(&ip_masks_map, &mask_candidate) != NULL) {
                u32 to_hash = daddr & ((1 << (32 - mask_length)) - 1);                  //extract bottom 32 - mask_length bits from ip
                u32 hash = jhash_2words(to_hash, mask_length, config->random_salt);     //hash the bottom bits
                daddr = mask_candidate.mask + (hash >> mask_length);                 //assign the top 32-mask_length hashed bits
                break;  
            }
        }

        iph->saddr = bpf_htonl(saddr); 
        iph->daddr = bpf_htonl(daddr); 
    } 

    nh->pos += hdrsize; 
    return iph->protocol; 
}

SEC("xdp_packet_parser")
int xdp_parser_func(struct xdp_md *ctx) {
    u32 key = 0; 
    anonymization_config *config = bpf_map_lookup_elem(&config_map, &key); 
    if(!config) {
        // char not_found[MAX_LEN] = "Anonymization config lookup failed\n"; 
        // bpf_trace_printk(not_found, sizeof(not_found)); 
        return XDP_ABORTED; 
    }

    void *data_end = (void *)(long)ctx->data_end; 
    void *data = (void *)(long)ctx->data; 

    struct hdr_cursor nh = {.pos = data}; 
    int nh_type; 

    nh_type = anonymize_ethhdr(&nh, data_end, config); 

    if(nh_type != bpf_htons(ETH_P_IP)) {
        return XDP_DROP; 
    }

    nh_type = anonymize_iphdr(&nh, data_end, config); 

    return XDP_DROP;  
}

