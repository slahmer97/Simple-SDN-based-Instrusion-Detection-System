import sys
import random
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.openflow.libopenflow_01 import *
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.recoco import Timer
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
import random
log = core.getLogger()
class MySwitch(object):
	def __init__(self):
		core.openflow.addListeners(self)
	
		self.connections = {} # connections to the switches.
                        # 1 is the learning switch that needs to detect scans as well.
		self.mac_to_port = {} # commutation table (mac address -> port number)

		self.tcp_destport = {} # (IP source, IP dest) -> TCP destination port


	def _handle_ConnectionUp(self, event):
		self.connections[event.dpid] = event.connection
		max_ports = len(event.connection.ports)
		log.debug("Switch %s has come up with %i ports", dpid_to_str(event.dpid), max_ports)
		
	def _handle_PacketIn (self, event):
		packet = event.parsed
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

		packet_in = event.ofp
		dpid = event.connection.dpid	
		self.act_like_switch(dpid, packet, packet_in)
	def handle_tcp_seg(self, dpid, packet, packet_in):
		mac_dst = packet.dst
		ip_from = packet.next.srcip
		ip_to = packet.next.dstip
		tcp_seg = packet.next.next
		srcport = tcp_seg.srcport
		dstport = tcp_seg.dstport
		# install a two drop rules
		# considering that our firewall blocks all src-dst trafic
		# we install rule base on ip, so all ip packets destined to dst will be dropped
		# we also install a rule for dropping layer two frames
		# PS: we can much just by the second one, we added the first one just in case
		# the scanner changes his mac addr
		# Inside the drop, we could also iterate over all available connections, and drop packets
		# which match with (src_ip,dst_ip)
		def drop ():
        		msg = of.ofp_flow_mod()
			msg.match.dl_type = 0x800
        		msg.match.nw_src = ip_from
			msg.match.nw_dst = ip_to
        		msg.priority = 32800
			self.connections[dpid].send(msg)
			
			msg = of.ofp_flow_mod()
			msg.match.dl_src = packet.src
			msg.match.dl_dst = packet.dst
			msg.priority = 32800
			self.connections[dpid].send(msg)
			log.info("Set a new drop rule for src : {} - {}".format(ip_from, ip_to))

		if (str(ip_from), str(ip_to)) not in self.tcp_destport:
			self.tcp_destport[(str(ip_from), str(ip_to))] = {}
			self.tcp_destport[(str(ip_from), str(ip_to))]["ST_SCAN"] = set()
			self.tcp_destport[(str(ip_from), str(ip_to))]["SYN"] = 0
			self.tcp_destport[(str(ip_from), str(ip_to))]["SYN-ACK"] = 0
 
		log.info("current log : {}".format(self.tcp_destport[(str(ip_from), str(ip_to))]))
		if tcp_seg.SYN or tcp_seg.ACK:
			if tcp_seg.SYN and not tcp_seg.ACK:
				self.tcp_destport[(str(ip_from), str(ip_to))]["SYN"] += 1
			if tcp_seg.SYN and tcp_seg.ACK:
				self.tcp_destport[(str(ip_from), str(ip_to))]["SYN-ACK"] += 1
			self.tcp_destport[(str(ip_from), str(ip_to))]["ST_SCAN"].add(dstport)
			if len(self.tcp_destport[(str(ip_from), str(ip_to))]["ST_SCAN"]) >= 5:
                                log.info("----->>>>>>>>>>>>>>>>>>>>installing rule to drop all connection attempts from {}".format(ip_from))
				drop()
		log.info("-----> Application : {} --> {}".format(srcport, dstport))
		self.resend_packet(packet_in, self.mac_to_port[dpid][str(mac_dst)] , self.connections[dpid])
		return False
        def is_it_a_web_server(self, ip):
		# TODO find another way to do this
		for i in range(1,10):
                	tmp = '10.0.0.1{}'.format(i)
			if tmp == ip :
				return True
		return False
	def is_it_webservermac(self, mac):
		# TODO find another way to do this
		for i in range(1,10):
                        tmp = '00:00:00:00:00:1{}'.format(i)
                        if tmp == mac :
                                return True
                return False

	
	def act_like_switch(self,dpid ,packet, packet_in):
		#check weither this switch has already switch_to_port entry
		if dpid not in self.mac_to_port :
			#mac_to_port 
			self.mac_to_port[dpid] = {}
    		print("mac_table for dpid{} : {}".format(dpid ,self.mac_to_port[dpid]))
    		in_port = packet_in.in_port
    		mac_src = packet.src
    		mac_dst = packet.dst
		self.mac_to_port[dpid][str(mac_src)] = in_port
		print("From : {}".format(str(mac_src)))
		is_a_web_sender = False
		# check if the received ethernet frame contains ip packet
		# if so, then check if the ip packet contains a tcp segment
		# if so, then we check if the sender was host and receiver is a webserver
		# if so we forward the packet to the firewall routine
		if isinstance(packet.next, ipv4) and isinstance(packet.next.next, tcp):
			ip_packet = packet.next
			tcp_seg = ip_packet.next
			from_ = ip_packet.srcip
			to_ = ip_packet.dstip
			tmp1 = self.is_it_a_web_server(str(to_))
			tmp2 = self.is_it_a_web_server(str(from_))
			if tmp2:
				is_a_web_sender = True
			
			#forward the tcp packet to the firewall routine
			if not tmp2:
				log.info("received a tcp/ip packet -- host->web : {} -> {}".format(from_, to_))
				self.handle_tcp_seg(dpid, packet, packet_in)
				return
    		def broadcast (perm = False):
        		msg = None
        		if perm :
           			msg = of.ofp_flow_mod()
           			match = of.ofp_match(dl_dst = mac_dst, dl_src = mac_src)
           			msg.match = match
        		else:
           			msg = of.ofp_packet_out()
        		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        		msg.data = packet_in
        		self.connections[dpid].send(msg)
    		if mac_dst.is_multicast:
			#broadcast addr
        		broadcast(False)
			return
		
    		if str(mac_dst) in self.mac_to_port[dpid]:
        		msg = of.ofp_flow_mod()
        		match = of.ofp_match(dl_dst = mac_dst, dl_src = mac_src)
        		msg.match = match
        		out_port = self.mac_to_port[dpid][str(mac_dst)]
        		msg.actions.append(of.ofp_action_output(port = out_port))
        		msg.data = packet_in
        		log.info("-------->installing flow entry {}:{}-> {}".format(str(mac_src),str(mac_dst), out_port))
        		self.connections[dpid].send(msg)
                	
			# here we have just added a rule (src_mac,dst_mac) -> port to our switch
			# we need to check if this frame came from a normal host, if so
			# we got to push another rules in order to forward packets that contain
			# tcp seg back to the controller, so it can detect scan
			# Like this we avoid overloading the controller with all network's packets
			# we forward just tcp packet coming from normal hosts
		        if (not is_a_web_sender) and not self.is_it_webservermac(str(mac_src)):
				log.info("not a webserver sender")
                                msg = of.ofp_flow_mod()
                        	match = of.ofp_match(dl_src = mac_src, dl_type=0x800, nw_proto = 0x6)
                        	msg.match = match
				# here we change the default priority, so when a tcp packet comes to the controller,
				# it will match the first one, which we just have added, and the current one
				# by using a higher priority, the controller will apply this rule (forward the packet to me)
				msg.priority = 32790
                        	msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
                        	log.debug("installing tcp entry...".format(str(mac_dst), of.OFPP_CONTROLLER))
                        	self.connections[dpid].send(msg)
    		else:
        		log.debug("no entry in mac_to_port for : {}".format(str(mac_dst)))
        		broadcast(False)


	def resend_packet (self, packet_in, out_port, connection):
		log.info("------------------------->resent packet")
		msg = of.ofp_packet_out()
		msg.data = packet_in
		msg.priority = 32791
		action = of.ofp_action_output(port = out_port)
		msg.actions.append(action)
		connection.send(msg)

def launch():
	core.registerNew(MySwitch)
