import logging

PcapWrapper = None

class BasePcapWrapper(object):

	def __init__(self, filters=None):
		if filters is not None:
			if isinstance(filters, basestring):
				filters = [filters]

			for f in filters:
				self._apply_filter(f)

	def _apply_filter(self, filter):
		pass

	@property
	def stats(self):
		return None
	
	@property
	def human_stats(self):
		if self.stats is None:
			return "No statistics availible"
		else:
			return '%d packets received, %d packets dropped, %d packets dropped by interface' % self.stats

def detect():
	global PcapWrapper
	PcapWrapper = create_pcap_wrapper()

def create_pcap_wrapper():	
	
	creator = None

	try:
		import pcap
		if hasattr(pcap, 'pcapObject'):
			#logging.debug('Detected pylibpcap.')
			creator = create_libpcap_wrapper
	except:
		pass

	try:
		import pcap
		if hasattr(pcap, 'pcap'):
			#logging.debug('Detected pypcap')
			creator = create_pypcap_wrapper
	except:
		pass
	
	if creator is None:
		logging.info('Unable to detect a pcap library')
	else:
		return creator()

def create_pypcap_wrapper():
	import pcap
	
	class PyPcapWrapper(BasePcapWrapper):
		def __init__(self, interface, filters=None):
			self.pc = pcap.pcap(name=interface, promisc=False, immediate=False)

			BasePcapWrapper.__init__(self, filters) 


		def _apply_filter(self, f):
			self.pc.setfilter(f)

		def loop(self, callback):

			def on_packet(ts, pkt):
				callback(pkt)		
			self.pc.loop(on_packet)

		@property
		def stats(self):
			try:
				return self.pc.stats()
			except:
				return None

	return PyPcapWrapper


def create_libpcap_wrapper():
	import pcap

	class LibPcapWrapper(BasePcapWrapper):
		def __init__(self, interface, filters=None):
			pcap.lookupnet(interface)

			self.pc = pcap.pcapObject()
			self.pc.open_live(interface, 3200, False, 0)
			
			BasePcapWrapper.__init__(self, filters)
		
		def _apply_filter(self, f):
			self.pc.setfilter(f, 0, 0)

		def loop(self, callback):

			def on_packet(plen, pkt, ts):
				callback(pkt)

			self.pc.setnonblock(1)
			try:
				while True:
					self.pc.dispatch(1, on_packet)
			except KeyboardInterrupt:
				logging.debug('Received keyboard interrupt.')

		@property
		def stats(self):
			return self.pc.stats()

	return LibPcapWrapper	

if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)

	detect()

	def on_packet(pkt):
		pass

	wrapper = PcapWrapper('eth0', 'tcp')
	

	logging.debug('looping')

	wrapper.loop(on_packet)
	
	logging.debug(wrapper.human_stats)

	
else:
	detect()
