#!/usr/bin/python

from concurrent import futures
from optparse import OptionParser
from pyroute2 import IPRoute, IPDB

import socket

import logging
import time
import grpc
import threading
import ast
import telnetlib

from ipaddress import IPv6Interface

# Folders
PROTO_FOLDER = "/home/user/repos/srv6-sdn-proto/"

import sys
# Add path of proto files
sys.path.append(PROTO_FOLDER)

import srv6_explicit_path_pb2_grpc
import srv6_explicit_path_pb2

import srv6_vpn_msg_pb2_grpc
import srv6_vpn_msg_pb2

import srv6_vpn_sb_pb2_grpc
import srv6_vpn_sb_pb2

from pyroute2.netlink.exceptions import NetlinkError

# Global variables definition

# rt_scopes represents the scope of the area where an address is valid
# The scopes available are defined in /etc/iproute2/rt_scopes
rt_scopes = {"global": 0, "nowhere": 255, "host": 254, "link": 253}

# Server reference
grpc_server = None
# Netlink socket
ip_route = None
ipdb = None
# Non-loopback interfaces
interfaces = []
# Mapping interface to ids
idxs = {}
# Logger reference
logger = logging.getLogger(__name__)
# Server ip and port
GRPC_IP = "::"
GRPC_PORT = 12345
# Debug option
SERVER_DEBUG = False
# Secure option
SECURE = False
# Server certificate
CERTIFICATE = "cert_server.pem"
# Server key
KEY = "key_server.pem"

# Code associated to the encap type seg6local in the Linux kernel
LWTUNNEL_ENCAP_SEG6_LOCAL = 7

# Netlink error codes
NETLINK_ERROR_FILE_EXISTS = 17
NETLINK_ERROR_NO_SUCH_PROCESS = 3
NETLINK_ERROR_NO_SUCH_DEVICE = 19
NETLINK_ERROR_OPERATION_NOT_SUPPORTED = 95

IPv6_EMULATION = False


class SRv6ExplicitPathHandler(srv6_explicit_path_pb2_grpc.SRv6ExplicitPathServicer):
    """gRPC request handler"""

    def Execute(self, op, request, context):
        logger.debug("config received:\n%s", request)
        # Let's push the routes
        for path in request.path:
            # Rebuild segments
            segments = []
            for srv6_segment in path.sr_path:
                segments.append(srv6_segment.segment)
            ip_route.route(op, dst=path.destination, oif=idxs[path.device],
               encap={'type':'seg6', 'mode':path.encapmode, 'segs':segments})
        # and create the response
        return srv6_explicit_path_pb2.SRv6EPReply(message="OK")

    def Create(self, request, context):
        # Handle Create operation 
        return self.Execute("add", request, context)

    def Remove(self, request, context):
        # Handle Remove operation 
        return self.Execute("del", request, context)


class SRv6SouthboundVPN(srv6_vpn_sb_pb2_grpc.SRv6SouthboundVPNServicer):
    """gRPC request handler"""

    def GetVPNs(self, request, context):
        # The list of Interface names
        interfaces = list()
        # Mapping interface index to interface name
        idx_to_vpn = dict()
        # VPNs
        vpns = dict()
        # Mapping table id to vpn names
        tableid_to_vpn = dict()
        # Scan all interfaces and search for VRFs
        for link in ip_route.get_links(): 
            # Get interface informations
            link_info = link.get_attr("IFLA_LINKINFO")
            # Get interface name
            intf_name = link.get_attr("IFLA_IFNAME")
            # Each VPN has an associated VRF
            # The name of the VPN is the same of the associated VRF
            # If the interface is a VRF, add to vpn names
            if link_info != None and \
                    link_info.get_attr("IFLA_INFO_KIND") == "vrf" and \
                    link_info.get_attr("IFLA_INFO_DATA") != None and \
                    link_info.get_attr("IFLA_INFO_DATA").get_attr("IFLA_VRF_TABLE") != None:
                # Get table id
                tableid = link_info.get_attr("IFLA_INFO_DATA").get_attr("IFLA_VRF_TABLE")
                # Save to the VPNs dict
                vpns[intf_name] = {
                  "sid": "",
                  "tableid": tableid,
                  "interfaces": set()
                }
                tableid_to_vpn[tableid] = intf_name
                intf_idx = ip_route.link_lookup(ifname=intf_name)[0]
                idx_to_vpn[intf_idx] = intf_name
        # Scan all interfaces and check interfaces associated to found VPNs
        for link in ip_route.get_links(): 
            # Get interface name
            intf_name = link.get_attr("IFLA_IFNAME")
            if link.get_attr("IFLA_MASTER") != None:
                # Get the index of the VRF to which the interface is associated 
                vrf_index = link.get_attr("IFLA_MASTER")
                # Get the name of the VRF, that is the name of the VPN
                vpn_name = idx_to_vpn[vrf_index]
                vpns[vpn_name]["interfaces"].add(intf_name)
        # SIDs
        # Scan all routes and search for the SIDs associated to the VPNs
        for route in ip_route.get_routes(table=1):
            # Get encap information and type
            encap_info = route.get_attr("RTA_ENCAP")
            encap_type = route.get_attr("RTA_ENCAP_TYPE")
            # If encap type is seg6local, this is a route 
            # associated to the egress node of a VPN
            if encap_type == LWTUNNEL_ENCAP_SEG6_LOCAL:
                # Destination prefix is the SID associated to a VPN
                # Retrieve the SID of some VPN
                sid = route.get_attr("RTA_DST")
                # Retrieve the table id associated to some VPN
                tableid = encap_info.get_attr("SEG6_LOCAL_TABLE")
                # Get VPN name
                name = tableid_to_vpn[tableid]
                # Save information to the VPN dict
                vpns[name]["sid"] = sid
        # Create the response
        response = srv6_vpn_msg_pb2.SRv6VPNList()
        for vpn_name in vpns:
            tableid = vpns[vpn_name]["tableid"]
            sid = vpns[vpn_name]["sid"]
            interfaces = vpns[vpn_name]["interfaces"]
            vpn = response.vpns.add()
            vpn.name = vpn_name
            vpn.tableid = int(tableid)
            vpn.sid = sid
            for intf in interfaces:    
                vpn.interfaces.append(intf)
        return response


    def CreateVPN(self, request, context):
        global IPv6_EMULATION
        logger.debug("config received:\n%s", request)
        # Extract the name of the VPN from the request
        name = str(request.name)
        # Extract the table id from the request
        tableid = request.tableid
        # Extract the sid from the request
        sid = str(request.sid)
        # Try to create a new VRF and associate to the specified routing table
        try:
            ip_route.link("add", ifname=name, kind="vrf", vrf_table=tableid)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # If the VRF already exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: VRF %s already exists" % name)
        # Enable the new VRF
        vpn_index = ip_route.link_lookup(ifname=name)[0]
        ip_route.link("set", index=vpn_index, state="up")
        # Add rule for incoming packets belonging to a VPN: lookup into the local SIDs table
        try:
            ip_route.rule("add", family=socket.AF_INET6, table=1, dst=sid, dst_len=64)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # If a rule for destination SID already exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: a rule for destination SID %s already exists" % sid)
        # Add rule for decapsulation: lookup into the table associated to the VPN
        try:
            if IPv6_EMULATION:
                ip_route.route("add", family=socket.AF_INET6, dst=sid, oif=idxs[interfaces[0]], table=1,
                                    encap={"type": "seg6local", "action": "End.DT6", "table": tableid})
            else:
                ip_route.route("add", family=socket.AF_INET6, dst=sid, oif=idxs[interfaces[0]], table=1,
                                    encap={"type": "seg6local", "action": "End.DT4", "table": tableid})
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # A route for destination SID already exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: a route for destination SID %s already exists" % sid)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def AddLocalInterfaceToVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract the name of the VPN from the request
        name = str(request.name)
        # Extract the interface from the request
        interface = str(request.interface)
        # Extract the ip address from the request
        ipaddr = str(request.ipaddr)
        # Get the index of the VPN
        vpn_index = ip_route.link_lookup(ifname=name)[0]
        # Get the index of the interface to be added
        intf_index = ip_route.link_lookup(ifname=interface)[0]
        # Delete all the prefix associated to the interface in the Quagga configuration
        for addr in ip_route.get_addr(family=socket.AF_INET6, index=intf_index):
            # Get the ip address
            ip = addr.get_attr("IFA_ADDRESS")
            # Get the prefix length
            prefixlen = addr.get("prefixlen")
            # Get the network prefix
            old_net = str(IPv6Interface(unicode(ip + "/" + str(prefixlen))).network)
            # Get the ip address
            old_ip = str(IPv6Interface(unicode(ip + "/" + str(prefixlen))))
            # Log to zebra daemon and remove the prefix
            # and delete the nd prefix and ip address associated to the interface
            try:
                password = "srv6"
                # Init telnet
                tn = telnetlib.Telnet("localhost", 2601)
                # Password
                tn.read_until("Password: ")
                tn.write("%s\r\n" % password)
                # Terminal length set to 0 to not have interruptions
                tn.write("terminal length 0\r\n")
                # Enable
                tn.write("enable\r\n")
                # Password
                tn.read_until("Password: ")
                tn.write("%s\r\n" % password)
                # Configure terminal
                tn.write("configure terminal\r\n")
                # Interface configuration
                tn.write("interface %s\r\n" % interface)
                # Remove the old IPv6 prefix
                tn.write("no ipv6 address %s\r\n" % old_ip)
                # Remove the old IPv6 prefix
                tn.write("no ipv6 nd prefix %s\r\n" % old_net)
                # Close interface configuration
                tn.write("q" + "\r\n")
                # Close configuration mode
                tn.write("q" + "\r\n")
                # Close privileged mode
                tn.write("q" + "\r\n")
                # Close telnet
                tn.close()
            except socket.error:
                print "Error: cannot establish a connection to %s on port %s" % (str("localhost"), str(port))
        # Add the new address and the new prefix
        new_ip = str(IPv6Interface(unicode(ipaddr)))
        new_net = str(IPv6Interface(unicode(ipaddr)).network)
        # Log to zebra daemon and add the prefix
        # and delete the nd prefix and ip address associated to the interface
        try:
            password = "srv6"
            # Init telnet
            tn = telnetlib.Telnet("localhost", 2601)
            # Password
            tn.read_until("Password: ")
            tn.write("%s\r\n" % password)
            # Terminal length set to 0 to not have interruptions
            tn.write("terminal length 0\r\n")
            # Enable
            tn.write("enable\r\n")
            # Password
            tn.read_until("Password: ")
            tn.write("%s\r\n" % password)
            # Configure terminal
            tn.write("configure terminal\r\n")
            # Interface configuration
            tn.write("interface %s\r\n" % interface)
            # Add the new IPv6 address
            tn.write("ipv6 address %s\r\n" % new_ip)
            # Add the new IPv6 prefix
            tn.write("ipv6 nd prefix %s\r\n" % new_net)
            # Close interface configuration
            tn.write("q" + "\r\n")
            # Close configuration mode
            tn.write("q" + "\r\n")
            # Close privileged mode
            tn.write("q" + "\r\n")
            # Close telnet
            tn.close()
        except socket.error:
            print "Error: cannot establish a connection to %s on port %s" % (str("localhost"), str(port))
        # Log to ospf6d daemon and remove the interface from the ospf advertisements
        # The subnet of a VPN site is a private subnet, so we don't advertise it
        try:
            password = "srv6"
            # Init telnet
            tn = telnetlib.Telnet("localhost", 2606)
            # Password
            tn.read_until("Password: ")
            tn.write("%s\r\n" % password)
            # Terminal length set to 0 to not have interruptions
            tn.write("terminal length 0\r\n")
            # Enable
            tn.write("enable\r\n")
            # Configure terminal
            tn.write("configure terminal\r\n")
            # Interface configuration
            tn.write("router ospf6\r\n")
            # Remove the interface from the link state messages
            tn.write("no interface %s area 0.0.0.0\r\n" % interface)
            # Close interface configuration
            tn.write("q" + "\r\n")
            # Close configuration mode
            tn.write("q" + "\r\n")
            # Close privileged mode
            tn.write("q" + "\r\n")
            # Close telnet
            tn.close()
        except socket.error:
            print "Error: cannot establish a connection to %s on port %s" % (str("localhost"), str(port))
        # Add local interface to the VRF associated to the VPN
        ip_route.link('set', index=intf_index, master=vpn_index)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def RemoveLocalInterfaceFromVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract the interface from the request
        interface = str(request.interface)
        # Delete all the prefix associated to the interface in the Quagga configuration
        intf_index = ip_route.link_lookup(ifname=interface)[0]
        for addr in ip_route.get_addr(family=socket.AF_INET6, index=intf_index):
            # Get the ip address
            ip = addr.get_attr("IFA_ADDRESS")
            # Get the prefix length
            prefixlen = addr.get("prefixlen")
            # Get the network prefix
            old_net = str(IPv6Interface(unicode(ip + "/" + str(prefixlen))).network)
            # Get the ip address
            old_ip = str(IPv6Interface(unicode(ip + "/" + str(prefixlen))))
            # Log to zebra daemon and remove the prefix
            # and delete the nd prefix and ip address associated to the interface
            try:
                password = "srv6"
                # Init telnet
                tn = telnetlib.Telnet("localhost", 2601)
                # Password
                tn.read_until("Password: ")
                tn.write("%s\r\n" % password)
                # Terminal length set to 0 to not have interruptions
                tn.write("terminal length 0\r\n")
                # Enable
                tn.write("enable\r\n")
                # Password
                tn.read_until("Password: ")
                tn.write("%s\r\n" % password)
                # Configure terminal
                tn.write("configure terminal\r\n")
                # Interface configuration
                tn.write("interface %s\r\n" % interface)
                # Remove the old IPv6 address
                tn.write("no ipv6 address %s\r\n" % old_ip)
                # Remove the old IPv6 prefix
                tn.write("no ipv6 nd prefix %s\r\n" % old_net)
                # Close interface configuration
                tn.write("q" + "\r\n")
                # Close configuration mode
                tn.write("q" + "\r\n")
                # Close privileged mode
                tn.write("q" + "\r\n")
                # Close telnet
                tn.close()
            except socket.error:
                print "Error: cannot establish a connection to %s on port %s" % (str("localhost"), str(port))
        # Log to ospf6d daemon and remove the interface from the ospf advertisements
        try:
            password = "srv6"
            # Init telnet
            tn = telnetlib.Telnet("localhost", 2606)
            # Password
            tn.read_until("Password: ")
            tn.write("%s\r\n" % password)
            # Terminal length set to 0 to not have interruptions
            tn.write("terminal length 0\r\n")
            # Enable
            tn.write("enable\r\n")
            # Configure terminal
            tn.write("configure terminal\r\n")
            # Interface configuration
            tn.write("router ospf6\r\n")
            # Insert the interface in the link state messages
            tn.write("interface %s area 0.0.0.0\r\n" % interface)
            # Close interface configuration
            tn.write("q" + "\r\n")
            # Close configuration mode
            tn.write("q" + "\r\n")
            # Close privileged mode
            tn.write("q" + "\r\n")
            # Close telnet
            tn.close()
        except socket.error:
            print "Error: cannot establish a connection to %s on port %s" % (str("localhost"), str(port))
        # Remove local interface from the VRF associated to the VPN
        ip_route.link('set', index=intf_index, master=0)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")
   
    def AddRemoteInterfaceToVPN(self, request, context):
        global IPv6_EMULATION
        logger.debug("config received:\n%s", request)
        # Extract the interfaces from the request
        interface = str(request.interface)
        # Extract the table id from the request
        tableid = request.tableid
        # Remove prefixlen from the sid
        sid = str(IPv6Interface(unicode(request.sid)).ip)
        # Add encapsulation rule for the packets destinated to remote site of the VPN
        try:
            if IPv6_EMULATION:
                ip_route.route("add", family=socket.AF_INET6, dst=interface, oif=idxs[interfaces[0]],
                  table=tableid, encap={'type':'seg6', 'mode':'encap', 'segs':[sid]})
            else:
                ip_route.route("add", family=socket.AF_INET, dst=interface, oif=idxs[interfaces[0]],
                  table=tableid, encap={'type':'seg6', 'mode':'encap', 'segs':[sid]})
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # If a route for remote destination prefix already exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: a route for remote destination %s already exists" % interface)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def RemoveRemoteInterfaceFromVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract interfaces and table id from the request
        interface = str(request.interface)
        tableid = request.tableid
        # Remove encapsulation rule from the table associated to the VPN
        try:
            ip_route.route("del", dst=interface, table=tableid)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: a route for remote destination %s does not exist" % interface)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def RemoveVPN(self, request, context):
        global IPv6_EMULATION
        logger.debug("Remove VPN request received:\n%s", request)
        # Extract name, table id and sid from the request
        name = str(request.name)
        tableid = request.tableid
        sid = str(request.sid)
        # Delete SID associated to the VPN from local SIDs table
        try:
            ip_route.route("del", family=socket.AF_INET6, dst=sid, table=1)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: the destination SID %s does not exist" % sid)
        # Delete SID rule for the routing policy associated to the VPN
        try:
            ip_route.rule("del", family=socket.AF_INET6, table=1, dst=sid, dst_len=64)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: the rule for destination SID %s does not exist" % sid)
        # Delete VRF associated to the VPN
        try:
            ip_route.link("del", ifname=name, kind="vrf", vrf_table=tableid)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: the VRF %s does not exist" % name)
        # Delete all remaining informations associated to the VPN
        if IPv6_EMULATION:
            ip_route.flush_routes(family=socket.AF_INET6, table=tableid)
        else:
            ip_route.flush_routes(family=socket.AF_INET, table=tableid)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def FlushVPNs(self, request, context):
          # Get all VPNs
          response = self.GetVPNs(request, context)
          # Delete all VPNs
          vpns = dict()
          for vpn in response.vpns:
              # Create the request
              delRequest = srv6_vpn_msg_pb2.RemoveVPNRequest()
              delRequest.name = vpn.name
              delRequest.tableid = vpn.tableid
              delRequest.sid = vpn.sid
              self.RemoveVPN(delRequest, context)
          # Create the response
          return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    # This method allows a gRPC client to get notified when a Netlink message is received
    def SubscribeNetlinkNotifications(self, request, context):
        # Create a new threading event
        # used to block the thread until a message is received
        e = threading.Event()
        # Netlink message
        self.nlmsg = dict()
        # Called when a new message is received from the Netlink socket
        def receive_netlink_message(ipdb, msg, action):
            # New message received
            # Convert the message to a dictionary representation
            self.nlmsg = ast.literal_eval(str(msg))
            # Set the event flag to True to notifiy the presence of a new message
            e.set()
        # Register the callback to be called when a new Netlink message is received
        ipdb.register_callback(receive_netlink_message)
        # Listen for Netlink messages
        while True:
            # Wait until a message from the Netlink socket is received
            e.wait()
            # New message received, create the response
            response = srv6_vpn_msg_pb2.NetlinkNotification()
            # Add the netlink message to the response
            for n in self.nlmsg:
                response.nlmsg[n] = str(self.nlmsg[n])
            # Send the message to the gRPC client
            yield response
            # No more messages
            self.nlmsg = ""
            # Set the event flag to False to block until a new Netlink message is received
            e.clear()

    # Get interfaces
    def GetInterfaces(self, request, context):
        # Get the interfaces
        links = dict()
        for link in ip_route.get_links():
            if link.get_attr("IFLA_LINKINFO") and link.get_attr("IFLA_LINKINFO").get_attr("IFLA_INFO_KIND") != "vrf":
                # Skip the VRFs
                # Get the index of the interface
                index = link.get("index")
                # Get the name of the interface
                name = link.get_attr("IFLA_IFNAME")
                # Get the MAC address of the interface
                macaddr = link.get_attr("IFLA_ADDRESS")
                # Save the interface
                links[index] = (name, macaddr)
        # Get the addresses assigned to the interfaces
        addrs = dict()
        for addr in ip_route.get_addr(family=socket.AF_INET6):
            # Get the index of the interface
            index = addr.get("index")
            # Get the IP address of the interface
            ipaddr = addr.get_attr("IFA_ADDRESS")
            # Save the address
            if addrs.get(index) == None:
                addrs[index] = list()
            addrs[index].append(ipaddr)
        # Mapping interface name to MAC address and IP address
        interfaces = dict()
        for index in links:
            name = links[index][0]
            macaddr = links[index][1]
            ipaddr = addrs[index]
            interfaces[name] = (macaddr, ipaddr)
        # Create the response
        response = srv6_vpn_msg_pb2.InterfacesList()
        for intf_name in interfaces:
            interface = response.interface.add()
            interface.name = intf_name
            interface.macaddr = interfaces[intf_name][0]
            for addr in interfaces[intf_name][1]:
                interface.ipaddr.append(addr)
        return response


# Start gRPC server
def start_server():
    # Configure gRPC server listener and ip route
    global grpc_server, ip_route, ipdb
    # Setup gRPC server
    if grpc_server is not None:
        logger.error("gRPC Server is already up and running")
    else:
        # Create the server and add the handler
        grpc_server = grpc.server(futures.ThreadPoolExecutor())
        srv6_explicit_path_pb2_grpc.add_SRv6ExplicitPathServicer_to_server(SRv6ExplicitPathHandler(),
                                                                            grpc_server)
        srv6_vpn_sb_pb2_grpc.add_SRv6SouthboundVPNServicer_to_server(SRv6SouthboundVPN(),
                                                                            grpc_server)
        # If secure we need to create a secure endpoint
        if SECURE:
            # Read key and certificate
            with open(KEY) as f:
               key = f.read()
            with open(CERTIFICATE) as f:
               certificate = f.read()
            # Create server ssl credentials
            grpc_server_credentials = grpc.ssl_server_credentials(((key, certificate,),))
            # Create a secure endpoint
            grpc_server.add_secure_port("[%s]:%s" %(GRPC_IP, GRPC_PORT), grpc_server_credentials)
        else:
            # Create an insecure endpoint
            grpc_server.add_insecure_port("[%s]:%s" %(GRPC_IP, GRPC_PORT))
    # Setup ip route
    if ip_route is not None:
        logger.error("IP Route is already setup")
    else:
        ip_route = IPRoute()
    # Setup ipdb
    if ipdb is not None:
        logger.error("IPDB is already setup")
    else:
       ipdb = IPDB()
    # Resolve the interfaces
    for link in ip_route.get_links():
        if link.get_attr("IFLA_IFNAME") != "lo":
            interfaces.append(link.get_attr("IFLA_IFNAME"))
    for interface in interfaces:
        idxs[interface] = ip_route.link_lookup(ifname=interface)[0]
    # Start the loop for gRPC
    logger.info("Listening gRPC")
    grpc_server.start()
    while True:
      time.sleep(5)


# Parse options
def parse_options():
    global SECURE, IPv6_EMULATION
    parser = OptionParser()
    parser.add_option("-d", "--debug", action="store_true", help="Activate debug logs")
    parser.add_option("-s", "--secure", action="store_true", help="Activate secure mode")
    parser.add_option("-i", "--ipv6", dest="ipv6_emulation", action="store_true", default=False, help="Enable IPv6 emulation")
    # Parse input parameters
    (options, args) = parser.parse_args()
    # Setup properly the logger
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
       logging.basicConfig(level=logging.INFO)
    # Setup properly the secure mode
    if options.secure:
        SECURE = True
    else:
        SECURE = False
    SERVER_DEBUG = logger.getEffectiveLevel() == logging.DEBUG
    IPv6_EMULATION = options.ipv6_emulation
    logger.info("SERVER_DEBUG:" + str(SERVER_DEBUG))


if __name__ == "__main__":
    parse_options()
    start_server()
