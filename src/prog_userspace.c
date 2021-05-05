#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <bpf/bpf.h>

#include <net/if.h>
#include <linux/if_link.h>

#include "../common/common_defines.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_structs.h"

const char *pin_basedir =  "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

#ifndef VALUE_MAX
#define VALUE_MAX   1024
#endif

int clear_ip_mask_map(int ip_mask_map_fd) {
    ip_mask key = {0}; 
    ip_mask next_key = {0}; 
    int err = 0; 
    while(err == 0) {
        err = bpf_map_get_next_key(ip_mask_map_fd, &key, &next_key); 
        bpf_map_delete_elem(ip_mask_map_fd, &key); 
        key = next_key; 
    }

    return 0; 
}

int parse_ip_masks(char *masks, bool is_src_ip, int ip_masks_map_fd, anonymization_config *anon_cfg) {
    char *mask_string = strtok(masks, ","); 
    ip_mask prefix_mask;
    __u32 mask_bytes[4];
    bool value = 1;

    while(mask_string != NULL) {
        int read = sscanf(mask_string, " %u.%u.%u.%u/%u", mask_bytes, mask_bytes+1, mask_bytes+2, mask_bytes+3, &(prefix_mask.len)); 
        if(read != 5) {
            fprintf(stderr, "ERR: badly formatted input mask\n");
            return -1;  
        }

        prefix_mask.mask = (mask_bytes[0] << 24) + (mask_bytes[1] << 16) + (mask_bytes[2] << 8) + mask_bytes[3]; 
        prefix_mask.mask &= (0xFFFFFFFF << (32 - prefix_mask.len)); 
        prefix_mask.is_src_mask = is_src_ip; 


        //print the scanned ip 
        mask_bytes[0] = prefix_mask.mask & 0xFF; 
        mask_bytes[1] = (prefix_mask.mask >> 8) & 0xFF; 
        mask_bytes[2] = (prefix_mask.mask >> 16) & 0xFF; 
        mask_bytes[3] = (prefix_mask.mask >> 24) & 0xFF; 
        fprintf(stderr, "scanned prefix_mask: %hhu.%hhu.%hhu.%hhu, len: %d, is_src_ip: %d\n", mask_bytes[3], mask_bytes[2], mask_bytes[1], mask_bytes[0], prefix_mask.len, prefix_mask.is_src_mask); 

        int err = bpf_map_update_elem(ip_masks_map_fd, &prefix_mask, &value, BPF_ANY); 
        if(err < 0) {
            fprintf(stderr, "ERR: could not write scanned ip mask to ip_mask_map\n"); 
            return err; 
        }

        if(is_src_ip) anon_cfg->src_ip_mask_lengths |= (1 << (prefix_mask.len - 1)); 
        else anon_cfg->dest_ip_mask_lengths |= (1 << (prefix_mask.len - 1)); 
        mask_string = strtok(NULL, ","); 
    }

    return 0; 
}

int parse_config(anonymization_config* anon_cfg, char* config_filename, int ip_masks_map_fd) {
    FILE *fp; 
    char *line = NULL; 
    size_t len = 0; 
    int line_count = 0; 

    fp = fopen(config_filename, "r"); 
    if(fp == NULL) {
        fprintf(stderr, "ERR: could not open config file: '%s' \n", config_filename); 
        return -1; 
    }

    while(getline(&line, &len, fp) != -1) {
        line_count++; 
        char *field_token = strtok(line, ":");
        char *value_token = strtok(NULL, "\n"); 

        if(field_token == NULL) {
            fprintf(stderr, "ERR: field is missing: line %d\n", line_count);
            return -1;  
        }

        if(strcmp(field_token, "anonymize_srcipv4") == 0) {
            int err = parse_ip_masks(value_token, true, ip_masks_map_fd, anon_cfg); 
            if(err < 0) {
                fprintf(stderr, "ERR: could not parse ip masks: line %d\n", line_count); 
                return err; 
            }
        } else if(strcmp(field_token, "anonymize_dstipv4") == 0) {
            int err = parse_ip_masks(value_token, false, ip_masks_map_fd, anon_cfg); 
            if(err < 0) {
                fprintf(stderr, "ERR: could not parse ip masks: line %d\n", line_count); 
                return err; 
            }
        } else {
            bool *cfg_field;
            if(strcmp(field_token, "anonymize_multicast_broadcast") == 0) {
                cfg_field = &(anon_cfg->anonymize_multicast_broadcast);
            } else if(strcmp(field_token, "anonymize_srcmac_oui") == 0) {
                cfg_field = &(anon_cfg->anonymize_srcmac_oui);
            } else if(strcmp(field_token, "anonymize_srcmac_id") == 0) {
                cfg_field = &(anon_cfg->anonymize_srcmac_id);
            } else if(strcmp(field_token, "anonymize_dstmac_oui") == 0) {
                cfg_field = &(anon_cfg->anonymize_dstmac_oui);
            } else if(strcmp(field_token, "anonymize_dstmac_id") == 0) {
                cfg_field = &(anon_cfg->anonymize_dstmac_id);
            } else if(strcmp(field_token, "preserve_prefix") == 0) {
                cfg_field = &(anon_cfg->preserve_prefix);
            } else if(strcmp(field_token, "anonymize_mac_in_arphdr") == 0) {
                cfg_field = &(anon_cfg->anonymize_mac_in_arphdr); 
            } else if(strcmp(field_token, "anonymize_ipv4_in_arphdr") == 0) {
                cfg_field = &(anon_cfg->anonymize_ipv4_in_arphdr); 
            } else {
                fprintf(stderr, "ERR: config field '%s' not recognized: line %d\n", field_token, line_count);
                return -1;  
            }
            if(value_token == NULL) {
                fprintf(stderr, "ERR: value is missing: line %d\n", line_count); 
                return -1; 
            }
            char value[VALUE_MAX]; 
            sscanf(value_token, " %s", value); 
            if(strcmp(value, "yes") == 0) {
                *cfg_field = true; 
            } else if(strcmp(value, "no") == 0) {
                *cfg_field = false; 
            } else {
                fprintf(stderr, "ERR: value '%s' not recognized: line %d\n", value, line_count); 
                return -1; 
            }
        }
    }

    fclose(fp); 
    return 0; 
}

int main() {
    int config_map_fd; 
    int ip_masks_map_fd;
    anonymization_config anon_cfg = {0}; 

    config_map_fd = open_bpf_map_file(pin_basedir, "config_map");
	if (config_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

    ip_masks_map_fd = open_bpf_map_file(pin_basedir, "ip_masks_map");
	if (ip_masks_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

    clear_ip_mask_map(ip_masks_map_fd); 

    int err = parse_config(&anon_cfg, "./anonymization_config.txt", ip_masks_map_fd); 
    if(err < 0) {
        return EXIT_FAILURE; 
    }

    int key = 0; 
    err = bpf_map_update_elem(config_map_fd, &key, &anon_cfg, BPF_ANY); 
    if(err < 0) {
        fprintf(stderr, "ERR: could not write to config_map\n"); 
        return EXIT_FAILURE;
    }

    
    return EXIT_OK; 
}