# srv6-sdn-data-plane

### Prerequisite ###

This project depends on [SRv6 Properties Generators](https://github.com/netgroup/srv6-properties-generators)

    > cd /home/user/workspace
    > git clone https://github.com/netgroup/srv6-properties-generators
    > cd srv6-properties-generators
    > sudo python setup.py install

This project depends on [SRv6 SDN Proto](https://github.com/netgroup/srv6-sdn-proto)

    > cd /home/user/workspace
    > git clone https://github.com/netgroup/srv6-sdn-proto

### SRv6 Southbound API ###

The project provides four different implementations of the SRv6 Southbound API: i) gRPC; ii) NETCONF; iii) REST; iv) SSH.
Each folder contains the server implementation.
The client implementation is contained in the project [srv6-sdn-control-plane](https://github.com/netgroup/srv6-sdn-control-plane).

#### NETCONF, REST, SSH ####

As of the server, it requires the init of the variable interfaces which defines the interface under the control of the SRv6Manager

    interfaces = ['eth0']

For the NETCONF and SSH implementation it is required to properly initialized USER and PASSWORD

    SSH_USER = 'srv6'
    SSH_PASSWORD = 'srv6'

Run the server

    > cd /home/user/workspace/srv6-controller/*

    Usage: *_server.py [options]

    Options:
        -h, --help    show this help message and exit
        -d, --debug   Activate debug logs
        -s, --secure  Activate secure mode

NETCONF and SSH implementation does support only secure mode

#### gRPC ####

It is necessary to set the variable PROTO_FOLDER placed in the file southbound/grpc/sb_grpc_server.py to point to the folder containing the proto files.

    PROTO_FOLDER = "../../../srv6-sdn-proto/"

Run the server

    > cd /home/user/workspace/srv6-sdn-data-plane/grpc

    Usage: sb_grpc_server.py [options]

    Options:
        -h, --help         Show this help message and exit
        -d, --debug        Activate debug logs
        -s, --secure       Activate secure mode
        -o, --ospf6d-port  The port that the ospf6d VTY is listening on
        -z, --zebra-port   The port that the zebra VTY is listening on
        -p, --quagga-pwd   Password of zebra/ospf6d quagga daemons
        -g, --grpc-ip      IP of the gRPC server
        -r, --grpc-port    Port of the gRPC server
        -c, --server-cert  Server certificate file
        -k, --server-key   Server key file
