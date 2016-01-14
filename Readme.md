0. Configuration
	a. Set up configuration in Config.mk (detailed instructions can be found in Config.mk)
	b. Set up addressing in router.c based on all addresses defined in env.h
		The first sniffer is responsible to the first valid ethernet interface in the device_list,
		the second sniffer is responsible for the second valid ethernet interface in the
		device_list, so and so on...
	c. Set up routing table lookup in routing.c function test should use rt_lookup_dummy(); 
		performance test and dynamic routing test should use createRT_2() and rt_lookup_2();
		configure all next hop for performance test. For dynamic routing test, if you want to
		see the initial routing table exchange, set metrix (cost) for destination node that 
		is not connected directly to this router as ROUTE_METRIX_MAX
1. Make
	Make key exchange test:
	$ make dh_1 && make dh_2

	Make router:
	$ make router

	Make sender/receiver with encryption:
	$ make pcap_sender && make pcap_receiver

2. File directory
	all header files are inside include/ folder. 
	all source files are inside src/ folder
	all generated .o files are inside obj/ folder

3. To generate packets, include packet_util.h
	for file transfer, use generate_file_packet()

4. To print packets, include printp.h
	call fprintp();

5. To run Symmetric key generation using DH:
	$ sudo ./dh_1 1 2 (One end of the link)
	$ sudo ./dh_2 2 1	(Other end of the link)

6. To run the sender and receiver
    $ sudo ./pcap_sender 
    $ sudo ./pcap_receiver 1 2

7. To run the router
	$ sudo ./router