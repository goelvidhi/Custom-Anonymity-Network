# Please set test mode and node identifier:
#
# For full-duplex test, set FUNCTION=1, everything else should be set to 0
#
# For performance test, set PERFORMANCE=1, and on which node this code sits on.
# for example, if the code is for router 1, then RTR1=1, and everything else
# should be set to zero
#
# For dynamic routing test, set PERFORMANCE=1 and DYNAMIC=1. Also set node
# identifier.
#
#


# Define test modes
	FUNCTION=0
	PERFORMANCE=0
	DYNAMIC=0



# Define node identifiers, uses these macros for 9-node performance test ONLY
	RTR1=0
	RTR2=0
	RTR3=0

	NODE1=0
	NODE2=0
	NODE3=0
	NODE4=0
	NODE5=0
	NODE6=0