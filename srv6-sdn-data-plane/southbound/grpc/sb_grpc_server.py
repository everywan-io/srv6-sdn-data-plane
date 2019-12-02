#!/usr/bin/python


# General imports
from argparse import ArgumentParser
import socket
import logging
import time
import grpc
import threading
import telnetlib
import sys
import os
from concurrent import futures
from optparse import OptionParser
from pyroute2 import IPRoute
from pyroute2 import IPDB
from socket import AF_INET
from socket import AF_INET6
from socket import AF_UNSPEC
from queue import Queue
from pyroute2.netlink.exceptions import NetlinkError
from pyroute2.netlink.nlsocket import Stats


################## Setup these variables ##################

# Path of the proto files
PROTO_FOLDER = '../../../srv6-sdn-proto/'

###########################################################

# Adjust relative paths
script_path = os.path.dirname(os.path.abspath(__file__))
PROTO_FOLDER = os.path.join(script_path, PROTO_FOLDER)

# Check paths
if PROTO_FOLDER == '':
    print('Error: Set PROTO_FOLDER variable '
          'in sb_grpc_server.py')
    sys.exit(-2)
if not os.path.exists(PROTO_FOLDER):
    print('Error: PROTO_FOLDER variable in sb_grpc_server.py '
          'points to a non existing folder\n')
    sys.exit(-2)

# Add path of proto files
sys.path.append(PROTO_FOLDER)

# SRv6 dependencies
import srv6_manager_pb2_grpc
import srv6_manager_pb2
from status_codes_pb2 import StatusCode
import network_events_listener_pb2
import network_events_listener_pb2_grpc
from sb_grpc_utils import InvalidAddressFamilyError

# Global variables definition

# Quagga configuration params
ZEBRA_PORT = 2601
OSPF6D_PORT = 2606
QUAGGA_PASSWORD = 'srv6'

# RT_SCOPES represents the scope of the area where an address is valid
# The scopes available are defined in /etc/iproute2/RT_SCOPES
RT_SCOPES = {
  'global': 0,
  'nowhere': 255,
  'host': 254,
  'link': 253
}

EVENT_TYPES = {
    'CONNECTION_ESTABLISHED': network_events_listener_pb2 \
                                  .NetworkEvent.CONNECTION_ESTABLISHED,
    'INTF_UP': network_events_listener_pb2.NetworkEvent.INTF_UP,
    'INTF_DOWN': network_events_listener_pb2.NetworkEvent.INTF_DOWN,
    'INTF_DEL': network_events_listener_pb2.NetworkEvent.INTF_DEL,
    'NEW_ADDR': network_events_listener_pb2.NetworkEvent.NEW_ADDR,
    'DEL_ADDR': network_events_listener_pb2.NetworkEvent.DEL_ADDR
}

class RTM_TYPES:
    RTN_UNSPEC = 0
    RTN_UNICAST = 1       # Gateway or direct route
    RTN_LOCAL = 2         # Accept locally
    RTN_BROADCAST = 3     # Accept locally as broadcast, send as broadcast
    RTN_ANYCAST = 4       # Accept locally as broadcast, but send as unicast
    RTN_MULTICAST = 5     # Multicast route
    RTN_BLACKHOLE = 6     # Drop
    RTN_UNREACHABLE = 7   # Destination is unreachable
    RTN_PROHIBIT = 8      # Administratively prohibited
    RTN_THROW = 9         # Not in this table
    RTN_NAT = 10          # Translate this address
    RTN_XRESOLVE = 11     # Use external resolver


ROUTE_TYPES = {
    'unicast': RTM_TYPES.RTN_UNICAST,
    'local': RTM_TYPES.RTN_LOCAL,
    'broadcast': RTM_TYPES.RTN_BROADCAST,
    'multicast': RTM_TYPES.RTN_MULTICAST,
    'throw': RTM_TYPES.RTN_THROW,
    'unreachable': RTM_TYPES.RTN_UNREACHABLE,
    'prohibit': RTM_TYPES.RTN_PROHIBIT,
    'blackhole': RTM_TYPES.RTN_BLACKHOLE,
    'nat': RTM_TYPES.RTN_NAT
}


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
GRPC_IP = '::'
GRPC_PORT = 12345
# Debug option
SERVER_DEBUG = False
# Secure option
SECURE = False
# Server certificate
CERTIFICATE = 'cert_server.pem'
# Server key
KEY = 'key_server.pem'

# Netlink error codes
NETLINK_ERROR_NO_SUCH_PROCESS = 3
NETLINK_ERROR_FILE_EXISTS = 17
NETLINK_ERROR_NO_SUCH_DEVICE = 19
NETLINK_ERROR_OPERATION_NOT_SUPPORTED = 95


class SRv6Manager(srv6_manager_pb2_grpc.SRv6ManagerServicer):
    '''gRPC request handler'''

    def HandleSRv6ExplicitPathRequest(self, op, request, context):
        logger.debug('config received:\n%s', request)
        # Perform operation
        try:
            if op == 'add' or 'del':
                # Let's push the routes
                for path in request.paths:
                    # Rebuild segments
                    segments = []
                    for srv6_segment in path.sr_path:
                        segments.append(srv6_segment.segment)
                    table = path.table
                    if path.table == -1:
                        table = None
                    if segments == []:
                        segments = ['::']
                    if path.device != '':
                        oif = idxs[path.device]
                    else:
                        oif = None
                    ip_route.route(op, dst=path.destination, oif=oif,
                                   table=table,
                                   encap={'type': 'seg6',
                                          'mode': path.encapmode,
                                          'segs': segments})
            else:
                # Operation unknown: this is a bug
                logger.error('Unrecognized operation: %s' % add)
                exit(-1)
            # and create the response
            logger.debug('Send response: OK')
            return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                logger.warning('Netlink error: File exists')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_FILE_EXISTS)
            elif e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                logger.warning('Netlink error: No such process')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_PROCESS)
            elif e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
                logger.warning('Netlink error: No such device')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_DEVICE)
            elif e.code == NETLINK_ERROR_OPERATION_NOT_SUPPORTED:
                logger.warning('Netlink error: Operation not supported')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_OPERATION_NOT_SUPPORTED)

    def HandleSRv6LocalProcessingFunctionRequest(self, op, request, context):
        logger.debug('config received:\n%s', request)
        # Let's process the request
        try:
            for function in request.functions:
                # Extract params from request
                segment = function.segment
                action = function.action
                nexthop = function.nexthop
                table = function.table
                interface = function.interface
                device = function.device
                localsid_table = function.localsid_table
                # Check optional params
                nexthop = nexthop if nexthop != '' else None
                table = table if table != -1 else None
                interface = interface if interface != '' else None
                # Perform operation
                if op == 'del':
                    # Delete a route
                    ip_route.route(op, family=AF_INET6, dst=segment,
                                   table=localsid_table)
                elif op == 'add':
                    # Add a new route
                    if action == 'End':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End'})
                    elif action == 'End.X':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.X',
                                              'nh6': nexthop})
                    elif action == 'End.T':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.T',
                                              'table': table})
                    elif action == 'End.DX2':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.DX2',
                                              'oif': interface})
                    elif action == 'End.DX6':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.DX6',
                                              'nh6': nexthop})
                    elif action == 'End.DX4':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.DX4',
                                              'nh4': nexthop})
                    elif action == 'End.DT6':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.DT6',
                                              'table': table})
                    elif action == 'End.DT4':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.DT4',
                                              'table': table})
                    elif action == 'End.DT46':
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.DT46',
                                              'table': table})
                    elif action == 'End.B6':
                        # Rebuild segments
                        segments = []
                        for srv6_segment in function.segs:
                            segments.append(srv6_segment.segment)
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.B6',
                                              'srh': {'segs': segments}})
                    elif action == 'End.B6.Encaps':
                        # Rebuild segments
                        segments = []
                        for srv6_segment in function.segs:
                            segments.append(srv6_segment.segment)
                        ip_route.route(op, family=AF_INET6, dst=segment,
                                       oif=idxs[device],
                                       table=localsid_table,
                                       encap={'type': 'seg6local',
                                              'action': 'End.B6.Encaps',
                                              'srh': {'segs': segments}})
                    else:
                        logger.debug('Error: Unrecognized action')
                        return (srv6_manager_pb2
                                .SRv6ManagerReply(status=StatusCode.STATUS_INVALID_ACTION))
                else:
                    # Operation unknown: this is a bug
                    logger.error('Unrecognized operation: %s' % add)
            # and create the response
            logger.debug('Send response: OK')
            return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                logger.warning('Netlink error: File exists')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_FILE_EXISTS)
            elif e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                logger.warning('Netlink error: No such process')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_PROCESS)
            elif e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
                logger.warning('Netlink error: No such device')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_DEVICE)
            elif e.code == NETLINK_ERROR_OPERATION_NOT_SUPPORTED:
                logger.warning('Netlink error: Operation not supported')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_OPERATION_NOT_SUPPORTED)

    def HandleIPRuleRequest(self, op, request, context):
        logger.debug('config received:\n%s', request)
        # Let's process the request
        try:
            if op == 'add' or op == 'del':
                for rule in request.rules:
                    # Extract params from the request
                    family = rule.family
                    table = rule.table
                    priority = rule.priority
                    action = rule.action
                    scope = rule.scope
                    destination = rule.destination
                    dst_len = rule.dst_len
                    source = rule.source
                    src_len = rule.src_len
                    in_interface = rule.in_interface
                    out_interface = rule.out_interface
                    # Check optional fields
                    table = table if table != -1 else None
                    priority = priority if priority != -1 else None
                    action = action if action != '' else None
                    scope = scope if scope != -1 else None
                    destination = destination if destination != '' else None
                    dst_len = dst_len if dst_len != -1 else None
                    source = source if source != '' else None
                    src_len = src_len if src_len != -1 else None
                    in_interface = in_interface if in_interface != '' else None
                    out_interface = out_interface if out_interface != '' else None
                    # Create or delete the rule
                    ip_route.rule(op, family=family, table=table,
                                  priority=priority, action=action,
                                  rtscope=scope,
                                  dst=destination, dst_len=dst_len,
                                  src=source, src_len=src_len,
                                  iifname=in_interface,
                                  oifname=out_interface)
            else:
                # Operation unknown: this is a bug
                logger.error('Unrecognized operation: %s' % add)
            # and create the response
            logger.debug('Send response: OK')
            return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                logger.warning('Netlink error: File exists')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_FILE_EXISTS)
            elif e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                logger.warning('Netlink error: No such process')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_PROCESS)
            elif e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
                logger.warning('Netlink error: No such device')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_DEVICE)
            elif e.code == NETLINK_ERROR_OPERATION_NOT_SUPPORTED:
                logger.warning('Netlink error: Operation not supported')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_OPERATION_NOT_SUPPORTED)

    def HandleIPRouteRequest(self, op, request, context):
        logger.debug('config received:\n%s', request)
        # Let's process the request
        try:
            if op == 'add' or op == 'del':
                for route in request.routes:
                    # Extract params from the request
                    family = route.family
                    tos = route.tos
                    type = route.type
                    table = route.table
                    scope = route.scope
                    proto = route.proto
                    destination = route.destination
                    dst_len = route.dst_len
                    preferred_source = route.preferred_source
                    src_len = route.src_len
                    in_interface = route.in_interface
                    out_interface = route.out_interface
                    gateway = route.gateway
                    # Check optional params
                    family = family if family != -1 else None
                    tos = tos if tos != '' else None
                    type = ROUTE_TYPES[type] if type != '' else None
                    table = table if table != -1 else None
                    scope = scope if scope != -1 else None
                    proto = proto if proto != -1 else None
                    destination = destination if destination != '' else None
                    dst_len = dst_len if dst_len != -1 else None
                    preferred_source = (preferred_source
                                        if preferred_source != '' else None)
                    src_len = src_len if src_len != -1 else None
                    in_interface = in_interface if in_interface != '' else None
                    out_interface = out_interface if out_interface != '' else None
                    gateway = gateway if gateway != '' else None
                    # Let's push the route
                    if destination is None and op == 'del':
                        # Destination not specified, delete all the routes
                        ip_route.flush_routes(table=table, tos=tos,
                                              scope=scope, type=type,
                                              proto=proto,
                                              prefsrc=preferred_source,
                                              src_len=src_len,
                                              iif=in_interface, oif=out_interface,
                                              gateway=gateway, family=family)
                    else:
                        # Create or delete the route
                        ip_route.route(op, table=table, tos=tos,
                                       scope=scope, type=type,
                                       proto=proto, dst=destination,
                                       prefsrc=preferred_source,
                                       src_len=src_len, dst_len=dst_len,
                                       iif=in_interface, oif=out_interface,
                                       gateway=gateway, family=family)
            else:
                # Operation unknown: this is a bug
                logger.error('Unrecognized operation: %s' % add)
            # and create the response
            logger.debug('Send response: OK')
            return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                logger.warning('Netlink error: File exists')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_FILE_EXISTS)
            elif e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                logger.warning('Netlink error: No such process')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_PROCESS)
            elif e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
                logger.warning('Netlink error: No such device')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_DEVICE)
            elif e.code == NETLINK_ERROR_OPERATION_NOT_SUPPORTED:
                logger.warning('Netlink error: Operation not supported')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_OPERATION_NOT_SUPPORTED)

    def HandleIPAddrRequest(self, op, request, context):
        logger.debug('config received:\n%s', request)
        # Let's process the request
        try:
            if op == 'add' or op == 'del':
                # Log to zebra daemon and add prefix
                # and ip address to the interface
                port = ZEBRA_PORT
                password = QUAGGA_PASSWORD
                try:
                    # Init telnet
                    tn = telnetlib.Telnet('localhost', port)
                    # Password
                    tn.read_until(b'Password: ')
                    tn.write(b'%s\r\n' % password.encode())
                    # Terminal length set to 0 to not have interruptions
                    tn.write(b'terminal length 0\r\n')
                    # Enable
                    tn.write(b'enable\r\n')
                    # Password
                    tn.read_until(b'Password: ')
                    tn.write(b'%s\r\n' % password.encode())
                    # Configure terminal
                    tn.write(b'configure terminal\r\n')
                    # Interface configuration
                    for addr in request.addrs:
                        # Extract the interface from the request
                        device = str(addr.device)
                        # Extract address family
                        family = addr.family
                        if family == -1:
                            if op == 'del':
                                family = AF_UNSPEC
                            else:
                                family = AF_INET
                        # Get IP address
                        ip = str(addr.ip_addr)
                        # Get network prefix
                        prefix = str(addr.net)
                        # Interface configuration
                        tn.write(b'interface %s\r\n' % device.encode())
                        if family == AF_INET6:
                            if op == 'del':
                                # Remove IPv6 address
                                tn.write(b'no ipv6 address %s\r\n' % ip.encode())
                                tn.write(b'no ipv6 nd prefix %s\r\n' % prefix.encode())
                            else:
                                # Add IPv6 address
                                tn.write(b'ipv6 address %s\r\n' % ip.encode())
                                tn.write(b'ipv6 nd prefix %s\r\n' % prefix.encode())
                        elif family == AF_INET:
                            if op == 'del':
                                # Remove IPv4 address
                                tn.write(b'no ip address %s\r\n' % ip.encode())
                            else:
                                # Add IPv4 address
                                tn.write(b'ip address %s\r\n' % ip.encode())
                        elif family == AF_UNSPEC:
                            if op == 'del':
                                # Remove IPv6 address
                                tn.write(b'no ipv6 address %s\r\n' % ip.encode())
                                tn.write(b'no ipv6 nd prefix %s\r\n' % prefix.encode())
                                # Remove IPv4 address
                                tn.write(b'no ip address %s\r\n' % ip.encode())
                            else:
                                raise InvalidAddressFamilyError
                        else:
                            raise InvalidAddressFamilyError
                        # Close interface configuration
                        tn.write(b'q\r\n')
                    # Close configuration mode
                    tn.write(b'q\r\n')
                    # Close privileged mode
                    tn.write(b'q\r\n')
                    # Read all
                    tn.read_all()
                    # Close telnet
                    tn.close()
                    logger.debug('Send response: OK')
                    return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
                except socket.error:
                    logger.debug('Send response: Unreachable zebra daemon')
                    return (srv6_manager_pb2
                            .SRv6ManagerReply(status=StatusCode.STATUS_UNREACHABLE_ZEBRA))
                except InvalidAddressFamilyError:
                    logger.debug('Send response: Invalid address family')
                    return (srv6_manager_pb2
                            .SRv6ManagerReply(status=StatusCode.STATUS_INVALID_ADDRESS))
            else:
                # Operation unknown: this is a bug
                logger.error('Unrecognized operation: %s' % add)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                logger.warning('Netlink error: File exists')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_FILE_EXISTS)
            elif e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                logger.warning('Netlink error: No such process')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_PROCESS)
            elif e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
                logger.warning('Netlink error: No such device')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_DEVICE)
            elif e.code == NETLINK_ERROR_OPERATION_NOT_SUPPORTED:
                logger.warning('Netlink error: Operation not supported')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_OPERATION_NOT_SUPPORTED)

    def HandleVRFDeviceRequest(self, op, request, context):
        logger.debug('config received:\n%s', request)
        # Let's process the request
        try:
            if op == 'add' or op == 'del':
                for device in request.devices:
                    ip_route.link(op, ifname=device.name,
                                  kind='vrf', vrf_table=device.table)
                    # Enable the new VRF
                    if op == 'add':
                        vrfindex = ip_route.link_lookup(ifname=device.name)[0]
                        ip_route.link('set', index=vrfindex, state='up')
                # and create the response
                if op == 'add':
                    return self.HandleVRFDeviceRequest('change', request, context)
                else:
                    logger.debug('Send response: OK')
                    return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
            elif op == 'change':
                for device in request.devices:
                    # Get the interfaces to be added to the VRF
                    interfaces = []
                    for interface in device.interfaces:
                        interfaces.append(interface)
                    # Get the VRF index
                    vrfindex = ip_route.link_lookup(ifname=device.name)[0]
                    # For each link in the VRF
                    for link in ip_route.get_links():
                        if link.get_attr('IFLA_MASTER') == vrfindex:
                            if link.get_attr('IFLA_IFNAME') in interfaces:
                                # The link belongs to the VRF
                                interfaces.remove(link.get_attr('IFLA_IFNAME'))
                            else:
                                # The link has to be removed from the VRF
                                ifindex = link.get('index')
                                ip_route.link('set', index=ifindex, master=0)
                    # Add the remaining links to the VRF
                    for interface in interfaces:
                        ifindex = ip_route.link_lookup(ifname=interface)[0]
                        ip_route.link('set', index=ifindex, master=vrfindex)
                    return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
            else:
                # Operation unknown: this is a bug
                logger.error('Unrecognized operation: %s' % add)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                logger.warning('Netlink error: File exists')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_FILE_EXISTS)
            elif e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                logger.warning('Netlink error: No such process')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_PROCESS)
            elif e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
                logger.warning('Netlink error: No such device')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_DEVICE)
            elif e.code == NETLINK_ERROR_OPERATION_NOT_SUPPORTED:
                logger.warning('Netlink error: Operation not supported')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_OPERATION_NOT_SUPPORTED)

    def HandleInterfaceRequest(self, op, request, context):
        logger.debug('config received:\n%s', request)
        # Let's process the request
        try:
            if op == 'change':
                # Handle change operation
                # Log to ospf6d daemon and remove the interface
                # from the ospf advertisements. The subnet of a VPN site
                # is a private subnet, so we don't advertise it
                port = OSPF6D_PORT
                password = QUAGGA_PASSWORD
                try:
                    # Init telnet
                    tn = telnetlib.Telnet('localhost', port)
                    # Password
                    tn.read_until(b'Password: ')
                    tn.write(b'%s\r\n' % password.encode())
                    # Terminal length set to 0 to not have interruptions
                    tn.write(b'terminal length 0\r\n')
                    # Enable
                    tn.write(b'enable\r\n')
                    # Configure terminal
                    tn.write(b'configure terminal\r\n')
                    # OSPF6 configuration
                    tn.write(b'router ospf6\r\n')
                    # Interface advertisements
                    for device in request.interfaces:
                        if device.ospf_adv:
                            # Add the interface to the link state messages
                            tn.write(b'interface %s area 0.0.0.0\r\n'
                                     % str(device.name).encode())
                        else:
                            # Remove the interface from the link state messages
                            tn.write(b'no interface %s area 0.0.0.0\r\n'
                                     % str(device.name).encode())
                    # Close interface configuration
                    tn.write(b'q\r\n')
                    # Close configuration mode
                    tn.write(b'q\r\n')
                    # Close privileged mode
                    tn.write(b'q\r\n')
                    # Read all
                    tn.read_all()
                    # Close telnet
                    tn.close()
                    logger.debug('Send response: OK')
                    return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
                except socket.error:
                    logger.debug('Send response: Unreachable ospf6d daemon')
                    return (srv6_manager_pb2
                            .SRv6ManagerReply(status=StatusCode.STATUS_UNREACHABLE_OSPF6D))
            elif op == 'get':
                # Handle get operation
                # Get the interfaces
                interfaces = []
                for interface in request.interfaces:
                    ifindex = ip_route.link_lookup(ifname=interface.name)[0]
                    interfaces.append(ifindex)
                links = dict()
                for link in ip_route.get_links(*interfaces):
                    if (link.get_attr('IFLA_LINKINFO') and
                        link.get_attr('IFLA_LINKINFO')
                            .get_attr('IFLA_INFO_KIND') != 'vrf'):
                        # Skip the VRFs
                        # Get the index of the interface
                        ifindex = link.get('index')
                        # Get the name of the interface
                        ifname = link.get_attr('IFLA_IFNAME')
                        # Get the MAC address of the interface
                        macaddr = link.get_attr('IFLA_ADDRESS')
                        # Get the state of the interface
                        state = link.get_attr('IFLA_OPERSTATE')
                        # Save the interface
                        links[ifindex] = (ifname, macaddr, state)
                # Get the addresses assigned to the interfaces
                addrs = dict()
                for addr in ip_route.get_addr():
                    # Get the index of the interface
                    ifindex = addr.get('index')
                    # Get the IP address of the interface
                    ipaddr = addr.get_attr('IFA_ADDRESS')
                    # Get prefix length
                    prefixlen = addr.get('prefixlen')
                    # IP/mask
                    ipaddr = '%s/%s' % (ipaddr, prefixlen)
                    # Save the address
                    if addrs.get(ifindex) is None:
                        addrs[ifindex] = list()
                    addrs[ifindex].append(ipaddr)
                # Mapping interface name to MAC address and IP address
                interfaces = dict()
                for ifindex in links:
                    ifname = links[ifindex][0]
                    macaddr = links[ifindex][1]
                    state = links[ifindex][2]
                    ipaddr = addrs[ifindex]
                    interfaces[ifname] = (macaddr, ipaddr, state, ifindex)
                # Create the response
                response = srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_SUCCESS)
                for ifname in interfaces:
                    interface = response.interfaces.add()
                    interface.index = int(interfaces[ifname][3])
                    interface.name = ifname
                    interface.macaddr = interfaces[ifname][0]
                    for addr in interfaces[ifname][1]:
                        interface.ipaddrs.append(addr)
                    interface.state = interfaces[ifname][2]
                logger.debug('Send response:\n%s', response)
                return response
            else:
                # Operation unknown: this is a bug
                logger.error('Unrecognized operation: %s' % add)
        except NetlinkError as e:
            if e.code == NETLINK_ERROR_FILE_EXISTS:
                logger.warning('Netlink error: File exists')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_FILE_EXISTS)
            elif e.code == NETLINK_ERROR_NO_SUCH_PROCESS:
                logger.warning('Netlink error: No such process')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_PROCESS)
            elif e.code == NETLINK_ERROR_NO_SUCH_DEVICE:
                logger.warning('Netlink error: No such device')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_NO_SUCH_DEVICE)
            elif e.code == NETLINK_ERROR_OPERATION_NOT_SUPPORTED:
                logger.warning('Netlink error: Operation not supported')
                return srv6_manager_pb2.SRv6ManagerReply(status=StatusCode.STATUS_OPERATION_NOT_SUPPORTED)

    def Execute(self, op, request, context):
        entity_type = request.entity_type
        # Handle operation
        # The operation to be executed depends on
        # the entity carried by the request message
        if entity_type == srv6_manager_pb2.SRv6ExplicitPath:
            request = request.srv6_ep_request
            return self.HandleSRv6ExplicitPathRequest(op, request, context)
        elif entity_type == srv6_manager_pb2.SRv6LocalProcessingFunction:
            request = request.srv6_lpf_request
            return (self.HandleSRv6LocalProcessingFunctionRequest(op, request,
                                                                  context))
        elif entity_type == srv6_manager_pb2.IPAddr:
            request = request.ipaddr_request
            return self.HandleIPAddrRequest(op, request, context)
        elif entity_type == srv6_manager_pb2.IPRule:
            request = request.iprule_request
            return self.HandleIPRuleRequest(op, request, context)
        elif entity_type == srv6_manager_pb2.IPRoute:
            request = request.iproute_request
            return self.HandleIPRouteRequest(op, request, context)
        elif entity_type == srv6_manager_pb2.VRFDevice:
            request = request.vrf_device_request
            return self.HandleVRFDeviceRequest(op, request, context)
        elif entity_type == srv6_manager_pb2.Interface:
            request = request.interface_request
            return self.HandleInterfaceRequest(op, request, context)
        else:
            return (srv6_manager_pb2
                    .SRv6ManagerReply(status=StatusCode.STATUS_INVALID_GRPC_REQUEST))

    def Create(self, request, context):
        # Handle Create operation
        return self.Execute('add', request, context)

    def Get(self, request, context):
        # Handle Create operation
        return self.Execute('get', request, context)

    def Update(self, request, context):
        # Handle Remove operation
        return self.Execute('change', request, context)

    def Remove(self, request, context):
        # Handle Remove operation
        return self.Execute('del', request, context)


class NetworkEventsListener(network_events_listener_pb2_grpc
                            .NetworkEventsListenerServicer):

    def Listen(self, request, context):
        logger.debug('config received:\n%s', request)
        # Send an ACK message to the client
        message = network_events_listener_pb2.NetworkEvent()
        message.type = EVENT_TYPES['CONNECTION_ESTABLISHED']
        yield message
        # Inizialize IPDB
        ipdb = IPDB()
        # Process event queue
        with ipdb.eventqueue() as evq:
            # Process messages
            for msg in evq:
                if not context.is_active():
                    logger.info('The client has been disconnected')
                    break
                ifindex = None
                ifname = None
                macaddr = None
                ipaddr = None
                prefixlen = None
                state = None
                if (msg.get_attr('IFLA_LINKINFO') is not None and
                    msg.get_attr('IFLA_LINKINFO')
                        .get_attr('IFLA_INFO_KIND') == 'vrf'):
                    # Skip VRF devices
                    continue
                # Convert the message to a dictionary representation
                nlmsg = eval(str(msg))
                if nlmsg['event'] == 'RTM_NEWLINK':
                    # New link message
                    # Extract attributes from the Netlink message
                    attrs = dict(nlmsg['attrs'])
                    # Extract the state of the interface
                    state = attrs.get('IFLA_OPERSTATE')
                    if state == 'UP':
                        type = 'INTF_UP'
                    elif state == 'DOWN':
                        type = 'INTF_DOWN'
                    else:
                        # Skip other events
                        continue
                    # Extract the interface index
                    ifindex = nlmsg['index']
                    # Extract the interface name
                    ifname = attrs.get('IFLA_IFNAME')
                    # Extract the MAC address of the interface
                    macaddr = attrs.get('IFLA_ADDRESS')
                elif nlmsg['event'] == 'RTM_DELLINK':
                    # Deleted link message
                    # Extract attributes from the Netlink message
                    attrs = dict(nlmsg['attrs'])
                    # Extract the state of the interface
                    type = 'INTF_DEL'
                    # Extract the index of the interface
                    ifindex = nlmsg['index']
                    # Extract the name of the interface
                    ifname = attrs.get('IFLA_IFNAME')
                    # Extract the MAC address of the interface
                    macaddr = attrs.get('IFLA_ADDRESS')
                elif nlmsg['event'] == 'RTM_NEWADDR':
                    # Deleted link message
                    # Extract attributes from the Netlink message
                    attrs = dict(nlmsg['attrs'])
                    # Extract the state of the interface
                    type = 'NEW_ADDR'
                    # Extract the index of the interface
                    ifindex = nlmsg['index']
                    # Extract the name of the interface
                    ifname = attrs.get('IFLA_IFNAME')
                    # Extract the IP address of the interface
                    ipaddr = attrs.get('IFA_ADDRESS')
                    # Extract the prefix length
                    prefixlen = nlmsg['prefixlen']
                elif nlmsg['event'] == 'RTM_DELADDR':
                    # Deleted link message
                    # Extract attributes from the Netlink message
                    attrs = dict(nlmsg['attrs'])
                    # Extract the state of the interface
                    type = 'DEL_ADDR'
                    # Extract the index of the interface
                    ifindex = nlmsg['index']
                    # Extract the IP address of the interface
                    ipaddr = attrs.get('IFA_ADDRESS')
                    # Extract the prefix length
                    prefixlen = nlmsg['prefixlen']
                else:
                    # Skip other events
                    continue
                # Create the response
                response = network_events_listener_pb2.NetworkEvent()
                response.interface.index = int(ifindex)
                if ifname is not None:
                    response.interface.name = ifname
                if macaddr is not None:
                    response.interface.macaddr = macaddr
                if ipaddr is not None:
                    response.interface.ipaddr = '%s/%s' % (ipaddr, prefixlen)
                response.type = EVENT_TYPES[type]
                # and send the response to the client
                logger.debug('Send response:\n%s' % response)
                yield response
        logger.info('Exiting from Listen()')


# Start gRPC server
def start_server():
    # Configure gRPC server listener and ip route
    global grpc_server, ip_route, ipdb
    # Setup gRPC server
    if grpc_server is not None:
        logger.error('gRPC Server is already up and running')
    else:
        # Create the server and add the handlers
        grpc_server = grpc.server(futures.ThreadPoolExecutor())
        (srv6_manager_pb2_grpc
         .add_SRv6ManagerServicer_to_server(SRv6Manager(),
                                            grpc_server))
        (network_events_listener_pb2_grpc
         .add_NetworkEventsListenerServicer_to_server(NetworkEventsListener(),
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
            grpc_server.add_secure_port('[%s]:%s' % (GRPC_IP, GRPC_PORT),
                                        grpc_server_credentials)
        else:
            # Create an insecure endpoint
            grpc_server.add_insecure_port('[%s]:%s' % (GRPC_IP, GRPC_PORT))
    # Setup ip route
    if ip_route is not None:
        logger.error('IP Route is already setup')
    else:
        ip_route = IPRoute()
    # Setup ipdb
    if ipdb is not None:
        logger.error('IPDB is already setup')
    else:
        ipdb = IPDB()
    # Resolve the interfaces
    for link in ip_route.get_links():
        if link.get_attr('IFLA_IFNAME') != 'lo':
            interfaces.append(link.get_attr('IFLA_IFNAME'))
    for interface in interfaces:
        idxs[interface] = ip_route.link_lookup(ifname=interface)[0]
    # Start the loop for gRPC
    logger.info('Listening gRPC')
    grpc_server.start()
    while True:
        time.sleep(5)


# Parse options
def parse_arguments():
    global SECURE, GRPC_IP, GRPC_PORT, CERTIFICATE, KEY, \
        ZEBRA_PORT, OSPF6D_PORT, QUAGGA_PASSWORD
    # Get parser
    parser = ArgumentParser(
        description='gRPC Southbound APIs for SRv6 Controller'
    )
    parser.add_argument(
        '-d', '--debug', action='store_true', help='Activate debug logs'
    )
    parser.add_argument(
        '-s', '--secure', action='store_true', help='Activate secure mode'
    )
    parser.add_argument(
        '-o', '--ospf6d-port', dest='ospf6d_port', action='store',
        default=OSPF6D_PORT,
        help='The port that the ospf6d VTY is listening on'
    )
    parser.add_argument(
        '-z', '--zebra-port', dest='zebra_port', action='store', default=ZEBRA_PORT,
        help='The port that the zebra VTY is listening on'
    )
    parser.add_argument(
        '-p', '--quagga-pwd', dest='quagga_pwd', action='store',
        default=QUAGGA_PASSWORD,
        help='Password of zebra/ospf6d quagga daemons'
    )
    parser.add_argument(
        '-g', '--grpc-ip', dest='grpc_ip', action='store', default=GRPC_IP,
        help='IP of the gRPC server'
    )
    parser.add_argument(
        '-r', '--grpc-port', dest='grpc_port', action='store', default=GRPC_PORT,
        help='Port of the gRPC server'
    )
    parser.add_argument(
        '-c', '--server-cert', dest='server_cert', action='store',
        default=CERTIFICATE, help='Server certificate file'
    )
    parser.add_argument(
        '-k', '--server-key', dest='server_key', action='store', default=KEY,
        help='Server key file'
    )
    # Parse input parameters
    args = parser.parse_args()
    # Setup properly the logger
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    # Setup properly the secure mode
    if args.secure:
        SECURE = True
    else:
        SECURE = False
    # gRPC IP
    GRPC_IP = args.grpc_ip
    # gRPC port
    GRPC_PORT = args.grpc_port
    # Password used to connect to quagga daemons
    QUAGGA_PASSWORD = args.quagga_pwd
    # Zebra port
    ZEBRA_PORT = args.zebra_port
    # ospf6d port
    OSPF6D_PORT = args.ospf6d_port
    # Server certificate
    CERTIFICATE = args.server_cert
    # Server key
    KEY = args.server_key
    # Debug settings
    SERVER_DEBUG = logger.getEffectiveLevel() == logging.DEBUG
    logger.info('SERVER_DEBUG:' + str(SERVER_DEBUG))


if __name__ == '__main__':
    parse_arguments()
    start_server()
