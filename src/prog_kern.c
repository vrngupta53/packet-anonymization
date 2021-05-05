#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../headers/jhash.h"
#include "../common/parsing_helpers.h"

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

struct arp_over_ipv4_hdr {
	__be16		        ar_hrd;		        /* format of hardware address	*/
	__be16		        ar_pro;		        /* format of protocol address	*/
	unsigned char	    ar_hln;		        /* length of hardware address	*/
	unsigned char	    ar_pln;		        /* length of protocol address	*/
    __be16		        ar_op;		        /* ARP opcode (command)		*/
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		    /* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		    /* target IP address		*/
};

static __always_inline void update_ip_checksum(struct iphdr *iph, u32 old_ip, u32 new_ip) {
    u32 csum = ~((u32)iph->check);
    csum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, csum); 
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    iph->check = ~csum; 
}

static __always_inline void anonymize_ethaddr_3_bytes(unsigned char *ethaddr, u32 salt) {
    u32 hash = jhash(ethaddr, 3, salt); 
    ethaddr[0] = (hash >> 24) & 0xFF; 
    ethaddr[1] = (hash >> 16) & 0xFF; 
    ethaddr[2] = (hash >> 8) & 0xFF; 
}

static __always_inline u32 anonymize_ipaddr(u32 ipaddr, u32 ip_mask_lengths, bool is_src_mask, u32 salt) {
    ip_mask mask_candidate = {0}; 

    for(int mask_length = 32; mask_length > 0; mask_length--) if(ip_mask_lengths & (1 << (mask_length-1))) {
        mask_candidate.mask = ipaddr & (0xFFFFFFFF << (32 - mask_length));           //extract top mask_length bits from ip
        mask_candidate.len = mask_length; 
        mask_candidate.is_src_mask = is_src_mask; 

        if(bpf_map_lookup_elem(&ip_masks_map, &mask_candidate) != NULL) {
            u32 to_hash = ipaddr & ((1 << (32 - mask_length)) - 1);                  //extract bottom 32 - mask_length bits from ip
            u32 hash = jhash_2words(to_hash, mask_length, salt);                     //hash the bottom bits
            ipaddr = mask_candidate.mask + (hash >> mask_length);                    //assign the top 32-mask_length hashed bits      
            break;  
        }
    }

    return ipaddr; 
}

static __always_inline int anonymize_ethhdr(struct hdr_cursor *nh, void *data_end, anonymization_config *config, bool *skip) {
    struct ethhdr *eth = nh->pos; 
    int hdrsize = sizeof(*eth); 
    struct vlan_hdr *vlh; 

    if(nh->pos + hdrsize > data_end) return -1; 

    bool broadcast_or_multicast = (eth->h_dest[0] & 1); 
    *skip = (broadcast_or_multicast && !config->anonymize_multicast_broadcast);
    
    if(!(*skip)) {
        if(config->anonymize_srcmac_oui) {
            anonymize_ethaddr_3_bytes(eth->h_source, config->random_salt); 
        }
        if(config->anonymize_dstmac_oui) {
            anonymize_ethaddr_3_bytes(eth->h_dest, config->random_salt); 
        }
        if(config->anonymize_srcmac_id) {
            anonymize_ethaddr_3_bytes(eth->h_source + 3, config->random_salt); 
        }
        if(config->anonymize_dstmac_id) {
            anonymize_ethaddr_3_bytes(eth->h_dest + 3, config->random_salt); 
        }
    }

    nh->pos += hdrsize; 
    vlh = nh->pos; 
    int h_proto = eth->h_proto; 

    for(int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if(!proto_is_vlan(h_proto)) 
            break; 
        if(vlh + 1 > data_end) 
            break; 
        h_proto = vlh->h_vlan_encapsulated_proto; 
        vlh++;  
    }

    return h_proto; 
}

static __always_inline int anonymize_iphdr(struct hdr_cursor *nh, void *data_end, anonymization_config *config) {
    struct iphdr *iph = nh->pos; 
    int hdrsize; 

    if(iph + 1 > data_end) return -1; 

    hdrsize = iph->ihl * 4; 
    if(hdrsize < sizeof(*iph)) return -1; 
    if(nh->pos + hdrsize > data_end) return -1; 

    if(config->preserve_prefix) {
        //check for source ip
        u32 saddr = bpf_ntohl(iph->saddr);
        saddr = anonymize_ipaddr(saddr, config->src_ip_mask_lengths, true, config->random_salt); 
        saddr = bpf_htonl(saddr);
        if(saddr != iph->saddr) {
            update_ip_checksum(iph, iph->saddr, saddr); 
            iph->saddr = saddr; 
        }

        //check for destination ip 
        u32 daddr = bpf_ntohl(iph->daddr); 
        daddr = anonymize_ipaddr(daddr, config->dest_ip_mask_lengths, false, config->random_salt); 
        daddr = bpf_htonl(daddr); 
        if(daddr != iph->daddr) {
            update_ip_checksum(iph, iph->daddr, daddr); 
            iph->daddr = daddr; 
        }
    } 

    nh->pos += hdrsize; 
    return iph->protocol; 
}

static __always_inline int anonymize_arphdr(struct hdr_cursor *nh, void *data_end, anonymization_config* config) {
    struct arp_over_ipv4_hdr *arph = nh->pos;
    int hdrsize = sizeof(*arph); 
    if(nh->pos + hdrsize > data_end) return -1; 
    if(arph->ar_hrd != bpf_htons(ARPHRD_ETHER) || arph->ar_pro != bpf_htons(ETH_P_IP)) return -1; 

    //anonymize mac addresses 
    if(config->anonymize_mac_in_arphdr) {
        if(config->anonymize_srcmac_oui) {
            anonymize_ethaddr_3_bytes(arph->ar_sha, config->random_salt); 
        }
        if(config->anonymize_dstmac_oui) {
            anonymize_ethaddr_3_bytes(arph->ar_tha, config->random_salt); 
        }
        if(config->anonymize_srcmac_id) {
            anonymize_ethaddr_3_bytes(arph->ar_sha + 3, config->random_salt); 
        }
        if(config->anonymize_dstmac_id) {
            anonymize_ethaddr_3_bytes(arph->ar_tha + 3, config->random_salt); 
        }
    }

    //anonymize ip addresses 
    if(config->anonymize_ipv4_in_arphdr) {
        if(config->preserve_prefix) {
            u32 saddr = 0; 
            u32 daddr = 0;
            for(int i = 0; i < 4; i++) {
                saddr += (u32)arph->ar_sip[i] << (8*(3-i)); 
                daddr += (u32)arph->ar_tip[i] << (8*(3-i)); 
            } 

            saddr = anonymize_ipaddr(saddr, config->src_ip_mask_lengths, true, config->random_salt); 
            daddr = anonymize_ipaddr(daddr, config->dest_ip_mask_lengths, false, config->random_salt); 

            for(int i = 0; i < 4; i++) {
                arph->ar_sip[i] = (saddr >> (8*(3-i))) & 0xFF; 
                arph->ar_tip[i] = (daddr >> (8*(3-i))) & 0xFF; 
            }
        }
    }

    return 0; 
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
    bool skip = false; 
    nh_type = anonymize_ethhdr(&nh, data_end, config, &skip); 
    if(nh_type < 0) {
        return XDP_DROP; 
    }

    if(skip) {
        return XDP_DROP; 
    }

    if(nh_type == bpf_htons(ETH_P_IP)) {
        nh_type = anonymize_iphdr(&nh, data_end, config); 
    } else if(nh_type == bpf_htons(ETH_P_ARP)) {
        nh_type = anonymize_arphdr(&nh, data_end, config); 
    } 

    return XDP_DROP;  
}

