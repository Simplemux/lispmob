in addition to README.md this is the information to use SIMPLEMUX.

There is a new feature that is the multiplexion at LISP tunnel.

To define this new feature is necessary fullfill the .conf file with the simplemux data as follow:

"operating-mode=xTRSM

...

simplemux {
        ipsrc=192.168.3.151
        ipdst=192.168.3.151
        lispsrc=155.210.157.151
        lispdst=155.210.157.159
        netsrc=192.168.3.0/24
        netdst=192.168.7.0/24
        num-pkt=10
        mtu-user=1500
        mtu-int=1500
        threshold=600
        period=100000
        ROHC-mode=0
}

simplemux {
...
}

...

simplemux {
...
}

Several simplemux can be define.

The meaning of each options is the follow:
        ipsrc: IP source of packets to multiplex
        ipdst: IP destination of packets to multiplex
        lispsrc: IP tunnel LISP source of packets to multiplex
        lispdst: IP tunnel LISP destination of packets to multiplex
        netsrc: Net source of packets to multiplex
        netdst: Net destination of packets to multiplex
        num-pkt: Maximun number of packets to multiplex
        mtu-user: Maximun number of byte to multiplex
        mtu-int: MTU redefine at the tunnel interface 
        threshold: Threshol number of byte to multiplex
        period: Maximun delay time to multiplex
        ROHC-mode: Compression mode at the header packets multiplexed

Not all this options are neccesary simultaneously.
