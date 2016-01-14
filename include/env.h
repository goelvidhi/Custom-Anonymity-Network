/**
 * CS 558L Final Project
 *
 * Node Environment
 */

#ifndef _ENV_H_
#define _ENV_H_

/* Define all the routing addresses and link keys here
 * link key is hard coded for full-duplex file transfer,
 * performance test, and dynamic routing, for simplicity.
 * Therefore we don't need key exchange everytime we test
 * our code.
 * 
 * Key exchange should be demoed separately*/
 
#if FUNCTION == 1
	#define RTR1_NODE1			0x0011
	#define RTR1_NODE2			0x0021
	#define RTR1_NODE3          0x0031
	#define NODE1_RTR1			0x0012
	#define NODE2_RTR1			0x0022
	#define NODE3_RTR1          0x0032

 	#define NODE1_RTR1_KEY		"node1"
 	#define NODE2_RTR1_KEY		"node2"
 	#define NODE3_RTR1_KEY		"node3"

#elif PERFORMANCE == 1
 	#define RTR1_ID				0xf001
 	#define RTR2_ID 			0xf002
 	#define RTR3_ID				0xf003

 	#define RTR1_NODE1			0x0011
	#define RTR1_NODE2			0x0021
 	#define NODE1_RTR1 			0x0012
 	#define NODE2_RTR1 			0x0022

 	#define RTR2_NODE3			0x0031
	#define RTR2_NODE4			0x0041
 	#define NODE3_RTR2 			0x0032
 	#define NODE4_RTR2 			0x0042

 	#define RTR3_NODE5			0x0051
	#define RTR3_NODE6			0x0061
 	#define NODE5_RTR3 			0x0052
 	#define NODE6_RTR3 			0x0062

 	#define RTR1_RTR2			0x0071
 	#define RTR2_RTR1			0x0072

 	#define RTR1_RTR3			0x0081
 	#define RTR3_RTR1			0x0082

 	#define RTR2_RTR3			0x0091
 	#define RTR3_RTR2			0x0092

 	#define NODE1_RTR1_KEY 		"node1"
 	#define NODE2_RTR1_KEY 		"node2"
 	#define NODE3_RTR2_KEY 		"node3"
 	#define NODE4_RTR2_KEY 		"node4"
 	#define NODE5_RTR3_KEY 		"node5"
 	#define NODE6_RTR3_KEY 		"node6"

 	#define RTR1_RTR2_KEY		"rtr12"
 	#define RTR1_RTR3_KEY		"rtr13"
 	#define RTR2_RTR3_KEY		"rtr23"
#else
# error "Please set either FUNCTION=1 OR PERFORMANCE=1"
#endif





#define PAYLOAD_SIZE       1400
#endif
