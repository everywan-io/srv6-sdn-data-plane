#!/usr/bin/python

from concurrent import futures
from optparse import OptionParser
from pyroute2 import IPRoute, IPDB
from google.protobuf import json_format

from socket import *

import logging
import time
import json
import grpc

import os
import subprocess

import srv6_explicit_path_pb2_grpc
import srv6_explicit_path_pb2

import srv6_vpn_pb2_grpc
import srv6_vpn_pb2

from pyroute2.netlink.exceptions import NetlinkError

import threading

# Global variables definition

# Server reference
grpc_server = None
# Netlink socket
ip_route = None
ipdb = None
# Non-loopback interfaces
interfaces = []
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


class SRv6VPNHandler(srv6_vpn_pb2_grpc.SRv6VPNHandlerServicer):
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
                table_id = link_info.get_attr("IFLA_INFO_DATA").get_attr("IFLA_VRF_TABLE")
                # Save to the VPNs dict
                vpns[intf_name] = {
                  "sid": "",
                  "table_id": table_id,
                  "interfaces": set()
                }
                tableid_to_vpn[table_id] = intf_name
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
                table_id = encap_info.get_attr("SEG6_LOCAL_TABLE")
                # Get VPN name
                name = tableid_to_vpn[table_id]
                # Save information to the VPN dict
                vpns[name]["sid"] = sid
        # Create the response
        response = srv6_vpn_pb2.SRv6VPNList()
        for vpn_name in vpns:
            table_id = vpns[vpn_name]["table_id"]
            sid = vpns[vpn_name]["sid"]
            interfaces = vpns[vpn_name]["interfaces"]
            vpn = response.vpns.add()
            vpn.name = vpn_name
            vpn.table_id = str(table_id)
            vpn.sid = sid
            for intf in interfaces:    
                vpn.interfaces.append(intf)
        return response


    def CreateVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract name, table id and sid from the request
        name = str(request.name)
        table_id = int(request.table_id)
        sid = str(request.sid)
        # Try to create a new VRF and associate to the provided routing table
        try:
            ip_route.link("add", ifname=name, kind="vrf", vrf_table=table_id)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # If the VRF already exists, create the error response
                details = "Cannot create VPN %s with table id %s and sid %s: " + \
                                  "the VRF %s already exists" % (name, table_id, sid, name)
                code = grpc.StatusCode.ALREADY_EXISTS
                context.abort(code, details)
        # Enable the new VRF
        vpn_index = ip_route.link_lookup(ifname=name)[0]
        ip_route.link("set", index=vpn_index, state="up")
        # Add rule for incoming packets belonging to a VPN: lookup into the local SIDs table
        try:
            ip_route.rule("add", family=AF_INET6, table=1, dst=sid, dst_len=64)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # If a rule for destination SID already exists, create the error response
                details = "Cannot create VPN %s with table id %s and sid %s: " + \
                    "a rule for destination SID %s already exists" % (name, table_id, sid, sid)
                code = grpc.StatusCode.ALREADY_EXISTS
                context.abort(code, details)
        # Add rule for decapsulation: lookup into the table associated to the VPN
        try:
            ip_route.route("add", family=AF_INET6, dst=sid, oif=idxs[interfaces[0]], table=1, 
                                encap={"type": "seg6local", "action": "End.DT6", "table": table_id})
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # A route for destination SID already exists, create the error response
                details = "Cannot create VPN %s with table id %s and sid %s: " + \
                    "a route for destination SID %s already exists" % (name, table_id, sid, sid)
                code = grpc.StatusCode.ALREADY_EXISTS
                context.abort(code, details)
        # Create the response
        return srv6_vpn_pb2.SRv6VPNReply(message="OK")

    def AddLocalInterfaceToVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract name, interface, ip and mask from the request
        name = str(request.name)
        interface = str(request.interface)
        # Add local interface to the VRF associated to the VPN
        vpn_index = ip_route.link_lookup(ifname=name)[0]
        intf_index = ip_route.link_lookup(ifname=interface)[0]
        ip_route.link('set', index=intf_index, master=vpn_index)
        # Create the response
        return srv6_vpn_pb2.SRv6VPNReply(message="OK")

    def RemoveLocalInterfaceFromVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract interface from the request
        interface = str(request.interface)
        # Remove local interface from the VRF associated to the VPN
        intf_index = ip_route.link_lookup(ifname=interface)[0]
        ip_route.link('set', index=intf_index, master=0)
        # Create the response
        return srv6_vpn_pb2.SRv6VPNReply(message="OK")
   
    def AddRemoteInterfaceToVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract interfaces, table_id and sid from the request
        interface = str(request.interface)
        table_id = int(request.table_id)
        sid = str(request.sid).split("/")[0] # Remove prefix from the sid
        # Add encapsulation rule for the packets destinated to remote site of the VPN
        try:
            ip_route.route("add", family=AF_INET6, dst=interface, oif=idxs[interfaces[0]],
              table=table_id, encap={'type':'seg6', 'mode':'encap', 'segs':[sid]})
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # If a route for remote destination prefix already exists, create the error response
                details = "Cannot create remote interface with prefix %s, table id %s and sid %s: " + \
                    "a route for remote destination prefix %s already exists" % (interface, table_id, sid, interface)
                code = grpc.StatusCode.ALREADY_EXISTS
                context.abort(code, details)
        # Create the response
        return srv6_vpn_pb2.SRv6VPNReply(message="OK")

    def RemoveRemoteInterfaceFromVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract interfaces and table id from the request
        interface = str(request.interface)
        table_id = int(request.table_id)
        # Remove encapsulation rule from the table associated to the VPN
        try:
            ip_route.route("del", dst=interface, table=table_id)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                details = "Cannot remove local interface %s with table_id %s: " + \
                    "the route for destination interface prefix %s does not exists" % (interface, table_id, interface)
                code = grpc.StatusCode.NOT_FOUND
                context.abort(code, details)
        # Create the response
        return srv6_vpn_pb2.SRv6VPNReply(message="OK")

    def RemoveVPN(self, request, context):
        logger.debug("Remove VPN request received:\n%s", request)
        # Extract name, table id and sid from the request
        name = str(request.name)
        table_id = int(request.table_id)
        sid = str(request.sid)
        # Delete SID associated to the VPN from local SIDs table
        try:
            ip_route.route("del", family=AF_INET6, dst=sid, table=1)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                details = "Cannot remove VPN %s: " + \
                    "the route for destination SID %s does not exists" % (name, sid)
                code = grpc.StatusCode.NOT_FOUND
                context.abort(code, details)
        # Delete SID rule for the routing policy associated to the VPN
        try:
            ip_route.rule("del", family=AF_INET6, table=1, dst=sid, dst_len=64)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                deatils = "Cannot remove VPN %s: " + \
                    "the rule for destination SID %s does not exists" % (name, sid)
                code = grpc.StatusCode.NOT_FOUND
                context.abort(code, details)
        # Delete VRF associated to the VPN
        try:
            ip_route.link("del", ifname=name, kind="vrf", vrf_table=table_id)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists, create the error response
                details = "Cannot remove VPN %s: " + \
                    "the VRF %s does not exists" % (name, name)
                code = grpc.StatusCode.NOT_FOUND
                context.abort(code, details)
        # Delete all remaining informations associated to the VPN
        ip_route.flush_routes(family=AF_INET6, table=table_id)
        # Create the response
        return srv6_vpn_pb2.SRv6VPNReply(message="OK")

    def FlushVPNs(self, request, context):
          # Get all VPNs
          response = self.GetVPNs(request, context)
          # Delete all VPNs
          vpns = dict()
          for vpn in response.vpns:
              # Create the request
              delRequest = srv6_vpn_pb2.RemoveVPNRequest()
              delRequest.name = vpn.name
              delRequest.table_id = vpn.table_id
              delRequest.sid = vpn.sid
              self.RemoveVPN(delRequest, context)
          # Create the response
          return srv6_vpn_pb2.SRv6VPNReply(message="OK")

    # This method allows a gRPC client to get notified when a Netlink message is received
    def SubscribeNetlinkNotifications(self, request, context):
        # Threading event: used to block the thread until a message is received
        e = threading.Event()
        self.netlink_msg = ""
        # Called when a new message is received from the Netlink socket
        def receive_netlink_message(ipdb, msg, action):
            # New message received
            self.netlink_msg = msg
            # Set the event flag to True
            e.set()
        # Register the callback
        ipdb.register_callback(receive_netlink_message)

        while True:
            # Wait until a message from the Netlink socket is received
            e.wait()
            # Send the message to the gRPC client
            yield srv6_vpn_pb2.NetlinkNotification(message=str(self.netlink_msg))
            # No more messages
            self.netlink_msg = ""
            # Set the event flag to False
            e.clear()


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
        srv6_vpn_pb2_grpc.add_SRv6VPNHandlerServicer_to_server(SRv6VPNHandler(),
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
    global SECURE
    parser = OptionParser()
    parser.add_option("-d", "--debug", action="store_true", help="Activate debug logs")
    parser.add_option("-s", "--secure", action="store_true", help="Activate secure mode")
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
    logger.info("SERVER_DEBUG:" + str(SERVER_DEBUG))


if __name__ == "__main__":
    parse_options()
    start_server()
