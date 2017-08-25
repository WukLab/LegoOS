obj-$(CONFIG_INFINIBAND_IPOIB)			+= ib_ipoib.o

ib_ipoib-y					:= ipoib_main.o
ib_ipoib-y					+= ipoib_ib.o
#ib_ipoib-y					+= ipoib_multicast.o
ib_ipoib-y					+= ipoib_verbs.o
#ib_ipoib-y					+= ipoib_vlan.o
#						   ipoib_ethtool.o
#						   ipoib_netlink.o
ib_ipoib-$(CONFIG_INFINIBAND_IPOIB_CM)		+= ipoib_cm.o
