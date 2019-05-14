#!/usr/bin/python

from concurrent import futures
from optparse import OptionParser
from pyroute2 import IPRoute, IPDB
from pyroute2.netlink.exceptions import NetlinkError

import socket

import logging
import time
import grpc
import threading
import ast
import telnetlib
import sys

from ipaddress import IPv4Interface, IPv6Interface

from socket import AF_INET, AF_INET6, AF_UNSPEC

from exception import InterfaceNotFoundError
from exception import AddressNotFoundError
from exception import AddressAlreadyAssignedError
from exception import InvalidAddressFamilyError
from exception import UnreachableZebraDaemonError
from exception import UnreachableOspf6DaemonError

# Folders
PROTO_FOLDER = "/home/user/repos/srv6-sdn-proto/"
# Add path of proto files
sys.path.append(PROTO_FOLDER)

import srv6_explicit_path_pb2_grpc
import srv6_explicit_path_pb2
import srv6_vpn_msg_pb2
import srv6_vpn_sb_pb2_grpc
import interface_manager_pb2_grpc
import interface_manager_pb2

from sb_grpc_utils import validateTableId
from sb_grpc_utils import getAddressFamily

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

ZEBRA_PORT = 2601
OSPF6D_PORT = 2606
PASSWORD = 'srv6'



def _addIPv6Address(ifname, ip):
    global ZEBRA_PORT, PASSWORD
    # Check if interface is valid
    if existsInterface(ifname=ifname) is False:
        raise InterfaceNotFoundError
    # Check if ip is a valid IPv6 address
    if getAddressFamily(ip) != AF_INET6:
        raise InvalidAddressFamilyError
    # Get network prefix
    net = str(IPv6Interface(unicode(ip)).network)
    # Get IPv6 address
    ip = str(IPv6Interface(unicode(ip)))
    # Log to zebra daemon and add prefix
    # and ip address to the interface
    port = ZEBRA_PORT
    password = PASSWORD
    try:
        # Init telnet
        tn = telnetlib.Telnet("localhost", port)
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
        tn.write("interface %s\r\n" % ifname)
        # Add the new IPv6 address
        tn.write("ipv6 address %s\r\n" % ip)
        # Add the new IPv6 prefix
        tn.write("ipv6 nd prefix %s\r\n" % net)
        # Close interface configuration
        tn.write("q" + "\r\n")
        # Close configuration mode
        tn.write("q" + "\r\n")
        # Close privileged mode
        tn.write("q" + "\r\n")
        # Read all
        tn.read_all()
        # Close telnet
        tn.close()
    except socket.error:
        raise UnreachableZebraDaemonError

def _removeIPv6Address(ifname, ip=None):
    global ZEBRA_PORT, PASSWORD
    # Check if interface is valid
    if not existsInterface(ifname=ifname):
        raise InterfaceNotFoundError
    # Check if ip is a valid IPv6 address
    if ip is not None and getAddressFamily(ip) != AF_INET6:
        raise InvalidAddressFamilyError
    # Let's check if the IPv6 address exists
    # Get the index of the interface
    ifindex = ip_route.link_lookup(ifname=ifname)[0]
    # Get the IP address
    ips = ip_route.get_addr(index=ifindex,
                            family=AF_INET6, address=ip)
    if ip is None and len(ips) == 0:
        # Address not found
        raise AddressNotFoundError
    # Log to zebra daemon and remove the prefix and delete
    # the nd prefix and ip address associated to the interface
    port = ZEBRA_PORT
    password = PASSWORD
    try:
        # Init telnet
        tn = telnetlib.Telnet("localhost", port)
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
        tn.write("interface %s\r\n" % ifname)
        # Remove the IP address and the nd prefix
        for ipaddr in ips:
            # Get the ip address
            ip = ipaddr.get_attr("IFA_ADDRESS")
            # Get the prefix length
            prefixlen = ipaddr.get("prefixlen")
            # Get network prefix
            net = str(IPv6Interface(unicode("%s/%s"
                                            % (ip, str(prefixlen))))
                      .network)
            # Get full IP address
            ip = str(IPv6Interface(unicode("%s/%s"
                                           % (ip, str(prefixlen)))))
            # Remove the IPv6 address
            tn.write("no ipv6 address %s\r\n" % ip)
            # Remove the IPv6 prefix
            tn.write("no ipv6 nd prefix %s\r\n" % net)
        # Close interface configuration
        tn.write("q" + "\r\n")
        # Close configuration mode
        tn.write("q" + "\r\n")
        # Close privileged mode
        tn.write("q" + "\r\n")
        # Read all
        tn.read_all()
        # Close telnet
        tn.close()
    except socket.error:
        raise UnreachableZebraDaemonError

def _addIPv4Address(ifname, ip):
    global ZEBRA_PORT, PASSWORD
    # Check if interface is valid
    if existsInterface(ifname=ifname) is False:
        raise InterfaceNotFoundError
    # Check if ip is a valid IPv4 address
    if getAddressFamily(ip) != AF_INET:
        raise InvalidAddressFamilyError
    # Get IPv4 address
    ip = str(IPv4Interface(unicode(ip)))
    # Get the index of the interface
    ifindex = ip_route.link_lookup(ifname=ifname)[0]
    # Check if the IP address exists
    if len(ip_route.get_addr(index=ifindex,
                             family=AF_INET6)) > 0:
        # The interface already has an IPv4 address
        raise AddressAlreadyAssignedError
    # Log to zebra daemon
    # and add the ip address to the interface
    port = ZEBRA_PORT
    password = PASSWORD
    try:
        # Init telnet
        tn = telnetlib.Telnet("localhost", port)
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
        tn.write("interface %s\r\n" % ifname)
        # Add the new IP address
        tn.write("ip address %s\r\n" % ip)
        # Close interface configuration
        tn.write("q" + "\r\n")
        # Close configuration mode
        tn.write("q" + "\r\n")
        # Close privileged mode
        tn.write("q" + "\r\n")
        # Read all
        tn.read_all()
        # Close telnet
        tn.close()
    except socket.error:
        raise UnreachableZebraDaemonError

def _removeIPv4Address(ifname, ip=None):
    global ZEBRA_PORT, PASSWORD
    # Check if interface is valid
    if existsInterface(ifname=ifname) is False:
        raise InterfaceNotFoundError
    # Check if ip is a valid IPv4 address
    if ip is not None and getAddressFamily(ip) != AF_INET:
        raise InvalidAddressFamilyError
    # Check if the IP address exists
    ifindex = ip_route.link_lookup(ifname=ifname)[0]
    ips = ip_route.get_addr(index=ifindex,
                            family=AF_INET, address=ip)
    if ip is not None and len(ips) == 0:
        # Address not found
        raise AddressNotFoundError
    # Log to zebra daemon and remove the prefix
    # and ip address associated to the interface
    port = ZEBRA_PORT
    password = PASSWORD
    try:
        # Init telnet
        tn = telnetlib.Telnet("localhost", port)
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
        tn.write("interface %s\r\n" % ifname)
        # Remove the IPv4 address
        for ipaddr in ips:
            # Get the ip address
            ip = ipaddr.get_attr("IFA_ADDRESS")
            # Get the prefix length
            prefixlen = ipaddr.get("prefixlen")
            # Get full IP address
            ip = str(IPv4Interface(unicode("%s/%s"
                                   % (ip, str(prefixlen)))))
            # Remove the IP address
            tn.write("no ip address %s\r\n" % ip)
        # Close interface configuration
        tn.write("q" + "\r\n")
        # Close configuration mode
        tn.write("q" + "\r\n")
        # Close privileged mode
        tn.write("q" + "\r\n")
        # Read all
        tn.read_all()
        # Close telnet
        tn.close()
    except socket.error:
        raise UnreachableZebraDaemonError

def _flushAddresses(ifname, family=AF_UNSPEC):
    # Check if interface is valid
    if not existsInterface(ifname=ifname):
        raise InterfaceNotFoundError
    if family == AF_INET6:
        # Remove all IPv6 addresses
        _removeIPv6Address(ifname=ifname)
    elif family == AF_INET:
        # Remove all IP addresses
        _removeIPv4Address(ifname=ifname)
    elif family == AF_UNSPEC:
        # Remove all IPv6 and IPv4 addresses
        _removeIPv6Address(ifname=ifname)
        _removeIPv4Address(ifname=ifname)
    else:
        # Family is invalid
        raise InvalidAddressFamilyError

def _turnOnInterfaceAdvertisements(ifname):
    global OSPF6D_PORT, PASSWORD
    # Check if interface is valid
    if existsInterface(ifname=ifname) is False:
        raise InterfaceNotFoundError
    # Log to ospf6d daemon and remove the interface
    # from the ospf advertisements. The subnet of a VPN site
    # is a private subnet, so we don't advertise it
    port = OSPF6D_PORT
    password = PASSWORD
    try:
        # Init telnet
        tn = telnetlib.Telnet("localhost", port)
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
        tn.write("interface %s area 0.0.0.0\r\n" % ifname)
        # Close interface configuration
        tn.write("q" + "\r\n")
        # Close configuration mode
        tn.write("q" + "\r\n")
        # Close privileged mode
        tn.write("q" + "\r\n")
        # Read all
        tn.read_all()
        # Close telnet
        tn.close()
    except socket.error:
        raise UnreachableOspf6DaemonError

def _turnOffInterfaceAdvertisements(ifname):
    global OSPF6D_PORT, PASSWORD
    # Check if interface is valid
    if existsInterface(ifname=ifname) is False:
        raise InterfaceNotFoundError
    # Log to ospf6d daemon and remove the interface
    # from the ospf advertisements. The subnet of a VPN site
    # is a private subnet, so we don't advertise it
    port = OSPF6D_PORT
    password = PASSWORD
    try:
        # Init telnet
        tn = telnetlib.Telnet("localhost", port)
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
        tn.write("no interface %s area 0.0.0.0\r\n" % ifname)
        # Close interface configuration
        tn.write("q" + "\r\n")
        # Close configuration mode
        tn.write("q" + "\r\n")
        # Close privileged mode
        tn.write("q" + "\r\n")
        # Read all
        tn.read_all()
        # Close telnet
        tn.close()
    except socket.error:
        raise UnreachableOspf6DaemonError


# Utility function to check if an interface exists
def existsInterface(ifname):
    try:
        ip_route.link('get', ifname=ifname)
        return True
    except NetlinkError as e:
        if e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
            return False


# Utility function to check if a VRF exists
def existsVRF(vrf):
    print "exists " + vrf
    if not existsInterface(ifname=vrf):
        print 1
        return False
    print 2
    # Get the interface
    link = ip_route.get_links(ifname=vrf)[0]
    print 3
    # Get interface informations
    link_info = link.get_attr("IFLA_LINKINFO")
    print 4
    # Each VPN has an associated VRF
    # The name of the VPN is the same of the associated VRF
    # If the interface is a VRF, add to vpn names
    if (link_info is not None and
            link_info.get_attr("IFLA_INFO_KIND") == "vrf"):
        print 5
        return True
    else:
        print 6
        return False


# Utility function to check if a VRF exists
def isInterfaceInVRF(ifname, vrf):
    print "is interface in vrf", 1
    if (existsInterface(ifname=ifname) is False or
            existsVRF(vrf=vrf) is False):
        print "is interface in vrf", 2
        return False
    vrf_index = ip_route.link_lookup(ifname=vrf)[0]
    print "is interface in vrf", 3
    # Scan all interfaces and check interfaces associated to found VPNs
    link = ip_route.get_links(ifname=ifname)[0]
    print "is interface in vrf", 4
    print link
    if link.get_attr("IFLA_MASTER") is not None:
        print "is interface in vrf", 5
        # Get the index of the VRF to which the interface is associated
        vrf_index2 = link.get_attr("IFLA_MASTER")
        print vrf_index
        print vrf_index2
        if vrf_index == vrf_index2:
            return True
    return False


# Utility function to check if a VRF exists
def isInterfaceInAnyVRF(ifname):
    if existsInterface(ifname=ifname) is False:
        return False
    # Scan all interfaces and check interfaces associated to found VPNs
    link = ip_route.get_links(ifname=ifname)[0]
    if link.get_attr("IFLA_MASTER") is not None:
        return True
    return False


class SRv6ExplicitPathHandler(srv6_explicit_path_pb2_grpc
                              .SRv6ExplicitPathServicer):
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
                           encap={'type': 'seg6',
                                  'mode': path.encapmode,
                                  'segs': segments})
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
            ifname = link.get_attr("IFLA_IFNAME")
            # Each VPN has an associated VRF
            # The name of the VPN is the same of the associated VRF
            # If the interface is a VRF, add to vpn names
            if (link_info is not None and
                    link_info.get_attr("IFLA_INFO_KIND") == "vrf" and
                    link_info.get_attr("IFLA_INFO_DATA") is not None and
                    (link_info.get_attr("IFLA_INFO_DATA")
                     .get_attr("IFLA_VRF_TABLE") is not None)):
                # Get table id
                tableid = (link_info.get_attr("IFLA_INFO_DATA")
                           .get_attr("IFLA_VRF_TABLE"))
                # Save to the VPNs dict
                vpns[ifname] = {
                  "sid": "",
                  "tableid": tableid,
                  "interfaces": set()
                }
                tableid_to_vpn[tableid] = ifname
                intf_idx = ip_route.link_lookup(ifname=ifname)[0]
                idx_to_vpn[intf_idx] = ifname
        # Scan all interfaces and check interfaces associated to found VPNs
        for link in ip_route.get_links():
            # Get interface name
            ifname = link.get_attr("IFLA_IFNAME")
            if link.get_attr("IFLA_MASTER") is not None:
                # Get the index of the VRF to which the interface is associated
                vrf_index = link.get_attr("IFLA_MASTER")
                # Get the name of the VRF, that is the name of the VPN
                vpn_name = idx_to_vpn[vrf_index]
                vpns[vpn_name]["interfaces"].add(ifname)
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
                vpn_name = tableid_to_vpn[tableid]
                # Save information to the VPN dict
                vpns[vpn_name]["sid"] = sid
        # Create the response
        response = srv6_vpn_msg_pb2.SRv6VPNList()
        for vpn_name in vpns:
            tableid = vpns[vpn_name]["tableid"]
            sid = vpns[vpn_name]["sid"]
            interfaces = vpns[vpn_name]["interfaces"]
            vpn = response.vpns.add()
            vpn.vpn_name = vpn_name
            vpn.tableid = int(tableid)
            vpn.sid = sid
            for intf in interfaces:
                vpn.interfaces.append(intf)
        return response

    def CreateVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract the name of the VPN from the request
        vpn_name = str(request.vpn_name)
        # Extract the table id from the request
        tableid = request.tableid
        # Extract the sid from the request
        sid = str(request.sid)
        # Check if the VPN exists
        if existsVRF(vrf=vpn_name):
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: VPN already exists"))
        if not validateTableId(tableid):
            # Invalid table ID
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid table ID"))
        if getAddressFamily(sid) != AF_INET6:
            # Invalid SID
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid SID"))
        try:
            # Add rule for incoming packets belonging to a VPN
            # lookup into the local SIDs table
            ip_route.rule("add", family=AF_INET6,
                          table=1, dst=sid, dst_len=64)
            # Add rule for decapsulation
            # lookup into the table associated to the VPN
            if True:
                ip_route.route("add", family=AF_INET6, dst=sid,
                               oif=idxs[interfaces[0]], table=1,
                               encap={"type": "seg6local", "action": "End.DT6",
                                      "table": tableid})
            else:
                ip_route.route("add", family=AF_INET6, dst=sid,
                               oif=idxs[interfaces[0]], table=1,
                               encap={"type": "seg6local", "action": "End.DT4",
                                      "table": tableid})
            # ip_route.route("add", family=AF_INET6, dst=sid,
            #                oif=idxs[interfaces[0]], table=1,
            #                encap={"type": "seg6local", "action": "End.DT46",
            #                "table": tableid})
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # The rule/route for destination SID already exists
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: Unavailable SID"))
            else:
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: %s" % e.code))
        # Create a new VRF and associate to the specified routing table
        try:
            ip_route.link("add", ifname=vpn_name,
                          kind="vrf", vrf_table=tableid)
            # Enable the new VRF
            vpn_index = ip_route.link_lookup(ifname=vpn_name)[0]
            ip_route.link("set", index=vpn_index, state="up")
        except NetlinkError as e:
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: %s" % e.code))
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def AddLocalInterfaceToVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract the name of the VPN from the request
        vpn_name = str(request.vpn_name)
        # Extract the interface from the request
        ifname = str(request.ifname)
        # Check if the vrf and the interface exist
        if not existsInterface(ifname=ifname):
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid interface"))
        if not existsVRF(vrf=vpn_name):
            print "violazione addadd localloca"
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid VPN"))
        if isInterfaceInAnyVRF(ifname=ifname):
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Interface "
                                  "already belongs to a VPN"))
        # Get the index of the VPN
        vpn_index = ip_route.link_lookup(ifname=vpn_name)[0]
        # Get the index of the interface to be added
        ifindex = ip_route.link_lookup(ifname=ifname)[0]
        try:
            # Delete all the addresses associated to the interface
            _flushAddresses(ifname=ifname)
            # Remove the interface from the ospf advertisements
            # The subnet of a VPN site is a private subnet
            # we don't advertise it
            _turnOffInterfaceAdvertisements(ifname=ifname)
        except InterfaceNotFoundError:
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid interface"))
        except UnreachableZebraDaemonError:
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Unreachable zebra daemon"))
        except UnreachableOspf6DaemonError:
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Unreachable ospf6d daemon"))
        # Add local interface to the VRF associated to the VPN
        ip_route.link('set', index=ifindex, master=vpn_index)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def RemoveLocalInterfaceFromVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract the name of the VPN from the request
        vpn_name = str(request.vpn_name)
        # Extract the interface from the request
        ifname = str(request.ifname)
        # Check if the vrf and the interface exist
        if not existsInterface(ifname=ifname):
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid interface"))
        if not existsVRF(vrf=vpn_name):
            print "violazione remove loca"
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid VPN"))
        if not isInterfaceInVRF(ifname=ifname, vrf=vpn_name):
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Interface "
                                  "does not belong to the VPN"))
        # Get the index of the interface to be removed
        ifindex = ip_route.link_lookup(ifname=ifname)[0]
        try:
            # Delete all the addresses associated to the interface
            _flushAddresses(ifname=ifname)
            # Add the interface to the ospf advertisements
            _turnOnInterfaceAdvertisements(ifname=ifname)
        except InterfaceNotFoundError:
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid interface"))
        except UnreachableZebraDaemonError:
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Unreachable zebra daemon"))
        except UnreachableOspf6DaemonError:
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Unreachable ospf6d daemon"))
        # Remove local interface from the VRF associated to the VPN
        ip_route.link('set', index=ifindex, master=0)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def AddRemoteInterfaceToVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract the VPN name from the request
        vpn_name = str(request.vpn_name)
        # Extract the interfaces from the request
        interface = str(request.interface)
        # Extract the table id from the request
        tableid = request.tableid
        # Remove prefixlen from the sid
        sid = str(IPv6Interface(unicode(request.sid)).ip)
        # Check if the VPN exists
        if not existsVRF(vrf=vpn_name):
            print "violazione add remote"
            return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: Invalid VPN")
        # Get address family
        family = getAddressFamily(interface)
        if family is None:
            # Address family not supported
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Unsupported address family"))
        if not validateTableId(tableid):
            # Invalid table ID
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid table ID"))
        if getAddressFamily(sid) != AF_INET6:
            # Invalid SID
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid SID"))
        # Add encapsulation rule for the packets
        # destinated to remote site of the VPN
        try:
            ip_route.route("add", family=family, dst=interface,
                           oif=idxs[interfaces[0]], table=tableid,
                           encap={'type': 'seg6', 'mode': 'encap',
                                  'segs': [sid]})
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                # If a route for remote destination prefix already exists
                # create the error response
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: Duplicate route"))
            else:
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: %s" % e.code))
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def RemoveRemoteInterfaceFromVPN(self, request, context):
        logger.debug("config received:\n%s", request)
        # Extract the VPN name from the request
        vpn_name = str(request.vpn_name)
        # Extract interfaces and table id from the request
        interface = str(request.interface)
        # Extract the table ID from the request
        tableid = request.tableid
        # Check if the VPN exists
        if not existsVRF(vrf=vpn_name):
            print "violazione remove remote"
            print vpn_name
            return srv6_vpn_msg_pb2.SRv6VPNReply(message="Error: Invalid VPN")
        # Get address family
        family = getAddressFamily(interface)
        if family is None:
            # Address family not supported
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Unsupported address family"))
        if not validateTableId(tableid):
            # Invalid table ID
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid table ID"))
        # Remove encapsulation rule from the table associated to the VPN
        try:
            ip_route.route("del", dst=interface, table=tableid)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists
                # create the error response
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: Route not found"))
            else:
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: %s" % e.code))
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def RemoveVPN(self, request, context):
        logger.debug("Remove VPN request received:\n%s", request)
        # Extract name, table id and sid from the request
        vpn_name = str(request.vpn_name)
        tableid = request.tableid
        sid = str(request.sid)
        # Check if the VPN exists
        if not existsVRF(vrf=vpn_name):
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: VPN not found"))
        if not validateTableId(tableid):
            # Invalid table ID
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid table ID"))
        if getAddressFamily(sid) != AF_INET6:
            # Invalid SID
            return (srv6_vpn_msg_pb2
                    .SRv6VPNReply(message="Error: Invalid SID"))
        # Delete SID associated to the VPN from local SIDs table
        try:
            ip_route.route("del", family=AF_INET6, dst=sid, table=1)
            # Delete SID rule for the routing policy associated to the VPN
            ip_route.rule("del", family=AF_INET6,
                          table=1, dst=sid, dst_len=64)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists
                # create the error response
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: Route not found"))
            else:
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: %s" % e.code))
        # Delete VRF associated to the VPN
        try:
            ip_route.link("del", ifname=vpn_name,
                          kind="vrf", vrf_table=tableid)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                # If the destination SID to delete does not exists
                # create the error response
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: VPN not found"))
            else:
                return (srv6_vpn_msg_pb2
                        .SRv6VPNReply(message="Error: %s" % e.code))
        # Delete all remaining informations associated to the VPN
        ip_route.flush_routes(family=AF_INET6, table=tableid)
        ip_route.flush_routes(family=AF_INET, table=tableid)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")

    def FlushVPNs(self, request, context):
        # Get all VPNs
        response = self.GetVPNs(request, context)
        # Delete all VPNs
        for vpn in response.vpns:
            # Create the request
            delRequest = srv6_vpn_msg_pb2.RemoveVPNRequest()
            delRequest.vpn_name = vpn.vpn_name
            delRequest.tableid = vpn.tableid
            delRequest.sid = vpn.sid
            self.RemoveVPN(delRequest, context)
        # Create the response
        return srv6_vpn_msg_pb2.SRv6VPNReply(message="OK")


class InterfaceManager(interface_manager_pb2_grpc
                       .InterfaceManagerServicer):

    def AddIPv6AddressToInterface(self, request, context):
        # Extract the interface from the request
        ifname = str(request.ifname)
        # Extract the ip address from the request
        ip = str(request.ipaddr)
        # Add IPv6 address
        try:
            _addIPv6Address(ifname=ifname, ip=ip)
        except InterfaceNotFoundError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid interface"))
        except InvalidAddressFamilyError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid address family"))
        except UnreachableZebraDaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable zebra daemon"))
        except UnreachableOspf6DaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable ospf6d daemon"))
        # Create the response
        return interface_manager_pb2.InterfaceManagerReply(message="OK")

    def RemoveIPv6AddressFromInterface(self, request, context):
        # Extract the interface from the request
        ifname = str(request.interface)
        # Extract the ip address from the request
        ip = str(request.ipaddr)
        # Remove IPv6 address
        try:
            _removeIPv6Address(ifname=ifname, ip=ip)
        except InterfaceNotFoundError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid interface"))
        except InvalidAddressFamilyError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid address family"))
        except AddressNotFoundError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Address not found"))
        except UnreachableZebraDaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable zebra daemon"))
        except UnreachableOspf6DaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable ospf6d daemon"))
        # Create the response
        return interface_manager_pb2.InterfaceManagerReply(message="OK")

    def AddIPv4AddressToInterface(self, request, context):
        # Extract the interface from the request
        ifname = str(request.interface)
        # Extract the ip address from the request
        ip = str(request.ipaddr)
        # Add IPv4 address
        try:
            _addIPv4Address(ifname=ifname, ip=ip)
        except InterfaceNotFoundError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid interface"))
        except InvalidAddressFamilyError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid address family"))
        except AddressAlreadyAssignedError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Address alreaady assigned"))
        except UnreachableZebraDaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable zebra daemon"))
        except UnreachableOspf6DaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable ospf6d daemon"))
        # Create the response
        return interface_manager_pb2.InterfaceManagerReply(message="OK")

    def RemoveIPv4AddressFromInterface(self, request, context):
        # Extract the interface from the request
        ifname = str(request.interface)
        # Extract the ip address from the request
        ip = str(request.ipaddr)
        # Remove IPv4 address
        try:
            _removeIPv4Address(ifname=ifname, ip=ip)
        except InterfaceNotFoundError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid interface"))
        except InvalidAddressFamilyError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Invalid address family"))
        except AddressNotFoundError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Address not found"))
        except UnreachableZebraDaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable zebra daemon"))
        except UnreachableOspf6DaemonError:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: Unreachable ospf6d daemon"))
        # Create the response
        return interface_manager_pb2.InterfaceManagerReply(message="OK")

    def AddIPAddressToInterface(self, request, context):
        # Extract the interface from the request
        # ifname = str(request.ifname) # UNUSED
        # Extract the ip address from the request
        ip = request.ipaddr
        # Get address family
        family = getAddressFamily(ip)
        # Process the request
        if family == AF_INET6:
            return self.AddIPv6AddressToInterface(request, context)
        elif family == AF_INET:
            return self.AddIPv4AddressToInterface(request, context)
        else:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: family not supported"))

    def RemoveIPAddressFromInterface(self, request, context):
        # Extract the interface from the request
        # ifname = str(request.ifname) # UNUSED
        # Extract the ip address from the request
        ip = request.ipaddr
        # Get address family
        family = getAddressFamily(ip)
        # Process the request
        if family == AF_INET6:
            return self.RemoveIPv6AddressFromInterface(request, context)
        elif family == AF_INET:
            return self.RemoveIPv4AddressFromInterface(request, context)
        else:
            return (interface_manager_pb2
                    .InterfaceManagerReply(message="Error: family not supported"))

    # This method allows a gRPC client
    # to get notified when a Netlink message is received
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
            # Set the event flag to True
            # to notifiy the presence of a new message
            e.set()
        # Register the callback to be called
        # when a new Netlink message is received
        ipdb.register_callback(receive_netlink_message)
        # Listen for Netlink messages
        while True:
            # Wait until a message from the Netlink socket is received
            e.wait()
            # New message received, create the response
            response = interface_manager_pb2.NetlinkNotification()
            # Add the netlink message to the response
            for n in self.nlmsg:
                response.nlmsg[n] = str(self.nlmsg[n])
            # Send the message to the gRPC client
            yield response
            # No more messages
            self.nlmsg = ""
            # Set the event flag to False to block
            # until a new Netlink message is received
            e.clear()

    # Get interfaces
    def GetInterfaces(self, request, context):
        # Get the interfaces
        links = dict()
        for link in ip_route.get_links():
            if (link.get_attr("IFLA_LINKINFO") and
                link.get_attr("IFLA_LINKINFO")
                    .get_attr("IFLA_INFO_KIND") != "vrf"):
                # Skip the VRFs
                # Get the index of the interface
                index = link.get("index")
                # Get the name of the interface
                ifname = link.get_attr("IFLA_IFNAME")
                # Get the MAC address of the interface
                macaddr = link.get_attr("IFLA_ADDRESS")
                # Save the interface
                links[index] = (ifname, macaddr)
        # Get the addresses assigned to the interfaces
        addrs = dict()
        for addr in ip_route.get_addr():
            # Get the index of the interface
            index = addr.get("index")
            # Get the IP address of the interface
            ipaddr = addr.get_attr("IFA_ADDRESS")
            # Save the address
            if addrs.get(index) is None:
                addrs[index] = list()
            addrs[index].append(ipaddr)
        # Mapping interface name to MAC address and IP address
        interfaces = dict()
        for index in links:
            ifname = links[index][0]
            macaddr = links[index][1]
            ipaddr = addrs[index]
            interfaces[ifname] = (macaddr, ipaddr)
        # Create the response
        response = interface_manager_pb2.InterfacesList()
        for ifname in interfaces:
            interface = response.interface.add()
            interface.ifname = ifname
            interface.macaddr = interfaces[ifname][0]
            for addr in interfaces[ifname][1]:
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
        (srv6_explicit_path_pb2_grpc
         .add_SRv6ExplicitPathServicer_to_server(SRv6ExplicitPathHandler(),
                                                 grpc_server))
        (srv6_vpn_sb_pb2_grpc
         .add_SRv6SouthboundVPNServicer_to_server(SRv6SouthboundVPN(),
                                                  grpc_server))
        (interface_manager_pb2_grpc
         .add_InterfaceManagerServicer_to_server(InterfaceManager(),
                                                 grpc_server))
        # If secure we need to create a secure endpoint
        if SECURE:
            # Read key and certificate
            with open(KEY) as f:
                key = f.read()
            with open(CERTIFICATE) as f:
                certificate = f.read()
            # Create server ssl credentials
            grpc_server_credentials = (grpc
                                       .ssl_server_credentials(((key,
                                                               certificate),)))
            # Create a secure endpoint
            grpc_server.add_secure_port("[%s]:%s" % (GRPC_IP, GRPC_PORT),
                                        grpc_server_credentials)
        else:
            # Create an insecure endpoint
            grpc_server.add_insecure_port("[%s]:%s" % (GRPC_IP, GRPC_PORT))
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
    parser.add_option("-d", "--debug", action="store_true",
                      help="Activate debug logs")
    parser.add_option("-s", "--secure", action="store_true",
                      help="Activate secure mode")
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
