# packet-anonymization
This is a tool to anonymize packets online before storing them on disk using the eBPF/XDP hook in the linux kernel.  
It requires linux kernel version 5.10 or higher to function. 

## Setup Instructions
Install dependencies(for Ubuntu). For other distributions, you can follow the dependency setup from this [tutorial](https://github.com/xdp-project/xdp-tutorial) and then continue these steps. 
    
    sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
    sudo apt install linux-tools-$(uname -r)
    sudo apt install linux-headers-$(uname -r)
    
Clone this repository and install the libbpf submodule. Then edit the `src/anonymization_config.txt` file as per your requirement. 

    git clone git@github.com:vrngupta53/packet-anonymization.git
    cd packet-anonymization
    git submodule init && git submodule update
    cd src
    make
    
Install xdp-loader and xdp-dump 

    git clone git@github.com:xdp-project/xdp-tools.git
    cd xdp-tools 
    git submodule init && git submodule update
    ./configure
    make 
    
Load the eBPF program `packet-anonymization/src/prog_kern.o` on the required network interface.
 
    cd xdp-loader
    sudo ./xdp-loader load <interface_name> /path/to/packet-anonymization/src/prog_kern.o --pin-path /sys/fs/bpf -vv
    
Now run the userspace program `packet-anonymization/src/prog_userspace` to load the anonymization configuration. 

    cd /path/to/packet-anonymization/src
    sudo ./prog_userspace
        
Now attach xdp-dump to the loaded eBPF program. The anonymized packet traces will be stored in `output_file.pcap`

    cd /path/to/xdp-tools/xdp-dump 
    sudo ./xdpdump --rx-capture exit -i <interface_name> -w /path/to/output_file.pcap -vv 
    
Now, if you need to change the anonymization, simply edit the anonymization_config.txt file and rerun prog_userspace. The eBPF program will automatically detect the change and use the new configuration. 
    
    
    
