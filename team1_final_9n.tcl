set ns [new Simulator]                  
source tb_compat.tcl

set node1 	[$ns node]
set node2 	[$ns node]
set node3 	[$ns node]
set node4 	[$ns node]
set node5 	[$ns node]
set node6 	[$ns node]

set rtr1 	[$ns node]
set rtr2 	[$ns node]
set rtr3 	[$ns node]

set link0 [$ns duplex-link $rtr1 $rtr2 1000Mb 5ms DropTail]
set link1 [$ns duplex-link $rtr1 $rtr3 1000Mb 5ms DropTail]
set link2 [$ns duplex-link $rtr2 $rtr3 1000Mb 5ms DropTail]

set link3 [$ns duplex-link $node1 $rtr1 1000Mb 5ms DropTail]
set link4 [$ns duplex-link $node2 $rtr1 1000Mb 5ms DropTail]

set link5 [$ns duplex-link $node3 $rtr2 1000Mb 5ms DropTail]
set link6 [$ns duplex-link $node4 $rtr2 1000Mb 5ms DropTail]

set link7 [$ns duplex-link $node5 $rtr3 1000Mb 5ms DropTail]
set link8 [$ns duplex-link $node6 $rtr3 1000Mb 5ms DropTail]

tb-set-link-loss $link0 0.01
tb-set-link-loss $link1 0.01
tb-set-link-loss $link2 0.01
tb-set-link-loss $link3 0.01
tb-set-link-loss $link4 0.01
tb-set-link-loss $link5 0.01
tb-set-link-loss $link6 0.01
tb-set-link-loss $link7 0.01
tb-set-link-loss $link8 0.01



tb-set-node-os $rtr1 Ubuntu1204-64-STD
tb-set-node-os $rtr2 Ubuntu1204-64-STD
tb-set-node-os $rtr3 Ubuntu1204-64-STD
tb-set-node-os $node1 Ubuntu1204-64-STD
tb-set-node-os $node2 Ubuntu1204-64-STD
tb-set-node-os $node3 Ubuntu1204-64-STD
tb-set-node-os $node4 Ubuntu1204-64-STD
tb-set-node-os $node5 Ubuntu1204-64-STD
tb-set-node-os $node6 Ubuntu1204-64-STD

tb-set-hardware $rtr1 MicroCloud
tb-set-hardware $rtr2 MicroCloud
tb-set-hardware $rtr3 MicroCloud
tb-set-hardware $node1 MicroCloud
tb-set-hardware $node2 MicroCloud
tb-set-hardware $node3 MicroCloud
tb-set-hardware $node4 MicroCloud
tb-set-hardware $node5 MicroCloud
tb-set-hardware $node6 MicroCloud

$ns rtproto Manual
$ns run

