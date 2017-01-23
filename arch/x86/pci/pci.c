#include <lego/string.h>
#include <lego/bug.h>
#include <lego/pci.h>
#include <lego/kernel.h>
#include <asm/io.h>

// Flag to do "lspci" at bootup
static int pci_show_devs = 1;
static int pci_show_addrs = 1;

// PCI "configuration mechanism one"
static u32 pci_conf1_addr_ioport = 0x0cf8;
static u32 pci_conf1_data_ioport = 0x0cfc;
// Forward declarations
static int pci_bridge_attach(struct pci_dev *pcif);

// PCI driver table
struct pci_driver {
	u32 vendor, device;
	int (*attachfn) (struct pci_dev *pcif); /* New device inserted */
//	const struct pci_device_id *id_table;	/* must be non-NULL for probe to be called */
	void (*remove) (struct pci_dev *pcif);	/* Device removed (NULL if not a hot-plug capable driver) */
//	void (*shutdown) (struct pci_dev *pcif);
};

// pci_attach_class matches the class and subclass of a PCI device
struct pci_driver pci_attach_class[] = {
	{ PCI_CLASS_BRIDGE, PCI_SUBCLASS_BRIDGE_PCI, &pci_bridge_attach },
	{ 0, 0, 0 },
};

// pci_attach_vendor matches the vendor ID and device ID of a PCI device
struct pci_driver pci_attach_vendor[] = {
//	{ 0x8086, 0x100E, &pci_func_attach_E1000 }, // #define PCI_VENDOR_ID_INTEL 8086
//	{ 0x8086, 0x1015, &pci_func_attach_E1000 },
	{ 0x15b3, 0x1003, &mlx4_init_one }, // #define PCI_VENDOR_ID_MELLANOX 15b3
	{ 0, 0, 0 },
};

static void
pci_conf1_set_addr(u32 bus,
		   u32 dev,
		   u32 func,
		   u32 offset)
{
	BUG_ON(!(bus < 256));
	BUG_ON(!(dev < 32));
	BUG_ON(!(func < 8));
	BUG_ON(!(offset < 256));
	BUG_ON(!((offset & 0x3) == 0));

	u32 v = (1 << 31) |		// config-space
		(bus << 16) | (dev << 11) | (func << 8) | (offset);
	outl(v, pci_conf1_addr_ioport);
}

u32 pci_conf_read(struct pci_dev *f, u32 off, int len)
{
	u32 val;

	pci_conf1_set_addr(f->bus->busno, f->dev, f->func, off);
	switch (len) {
		case 1:
			val = inb(pci_conf1_data_ioport);
			break;
		case 2:
			val = inw(pci_conf1_data_ioport);
			break;
		case 3:
			val = inl(pci_conf1_data_ioport);
			break;
	}

	return val;
}

void pci_conf_write(struct pci_dev *f, u32 off, u32 v, int len)
{
	pci_conf1_set_addr(f->bus->busno, f->dev, f->func, off);
	switch (len) {
		case 1:
			outb(v, pci_conf1_data_ioport);
			break;
		case 2:
			outw(v, pci_conf1_data_ioport);
			break;
		case 3:
			outl(v, pci_conf1_data_ioport);
			break;
	}
	return;
}

static int __attribute__((warn_unused_result))
pci_attach_match(u32 vendor, u32 device,
		 struct pci_driver *list, struct pci_dev *pcif)
{
	u32 i;

	for (i = 0; list[i].attachfn; i++) {
		if (list[i].vendor == vendor && list[i].device == device) {
			int r = list[i].attachfn(pcif);
			if (r > 0)
				return r;
			if (r < 0)
				pr_debug("pci_attach_match: attaching "
					"%x.%x (%p): e\n",
					vendor, device, list[i].attachfn, r);
		}
	}
	//pr_debug("pci_attach_match %x.%x no match\n", vendor, device);
	return 0;
}

static int pci_attach(struct pci_dev *f)
{
	return
		pci_attach_match(PCI_CLASS(f->dev_class),
				 PCI_SUBCLASS(f->dev_class),
				 &pci_attach_class[0], f) ||
		pci_attach_match(PCI_VENDOR(f->dev_id),
				 PCI_PRODUCT(f->dev_id),
				 &pci_attach_vendor[0], f);
}

static const char *pci_class[] =
{
	[0x0] = "Unknown",
	[0x1] = "Storage controller",
	[0x2] = "Network controller",
	[0x3] = "Display controller",
	[0x4] = "Multimedia device",
	[0x5] = "Memory controller",
	[0x6] = "Bridge device",
};

static void pci_print_func(struct pci_dev *f)
{
	const char *class = pci_class[0];
	if (PCI_CLASS(f->dev_class) < sizeof(pci_class) / sizeof(pci_class[0]))
		class = pci_class[PCI_CLASS(f->dev_class)];

	pr_debug("PCI: %02x:%02x.%d: %04x:%04x: class: %x.%x (%s) irq: %d\n",
		f->bus->busno, f->dev, f->func,
		PCI_VENDOR(f->dev_id), PCI_PRODUCT(f->dev_id),
		PCI_CLASS(f->dev_class), PCI_SUBCLASS(f->dev_class), class,
		f->irq_line);
}

static int pci_scan_bus(struct pci_bus *bus)
{
	int totaldev = 0;
	struct pci_dev df;
	memset(&df, 0, sizeof(df));
	df.bus = bus;

	//pr_debug("pci_scan_bus enter bus %p\n", bus);
	for (df.dev = 0; df.dev < 32; df.dev++) {
		u32 bhlc = pci_conf_read(&df, PCI_BHLC_REG, 3);
		if (PCI_HDRTYPE_TYPE(bhlc) > 1)	    // Unsupported or no device
			continue;

		totaldev++;

		struct pci_dev f = df;
		for (f.func = 0; f.func < (PCI_HDRTYPE_MULTIFN(bhlc) ? 8 : 1);
		     f.func++) {
			struct pci_dev af = f;

			af.dev_id = pci_conf_read(&f, PCI_ID_REG, 3);
			if (PCI_VENDOR(af.dev_id) == 0xffff)
				continue;

			u32 intr = pci_conf_read(&af, PCI_INTERRUPT_REG, 3);
			af.irq_line = PCI_INTERRUPT_LINE(intr);

			af.dev_class = pci_conf_read(&af, PCI_CLASS_REG, 3);
			if (pci_show_devs)
				pci_print_func(&af);
			pci_attach(&af);
		}
	}
	//pr_debug("pci_scan_bus exit bus %p\n", bus);

	return totaldev;
}

static int pci_bridge_attach(struct pci_dev *pcif)
{
	u32 ioreg  = pci_conf_read(pcif, PCI_BRIDGE_STATIO_REG, 3);
	u32 busreg = pci_conf_read(pcif, PCI_BRIDGE_BUS_REG, 3);

	if (PCI_BRIDGE_IO_32BITS(ioreg)) {
		pr_debug("PCI: %02x:%02x.%d: 32-bit bridge IO not supported.\n",
			pcif->bus->busno, pcif->dev, pcif->func);
		return 0;
	}

	struct pci_bus nbus;
	memset(&nbus, 0, sizeof(nbus));
	nbus.parent_bridge = pcif;
	nbus.busno = (busreg >> PCI_BRIDGE_BUS_SECONDARY_SHIFT) & 0xff;

	if (pci_show_devs)
		pr_debug("PCI: %02x:%02x.%d: bridge to PCI bus %d--%d\n",
			pcif->bus->busno, pcif->dev, pcif->func,
			nbus.busno,
			(busreg >> PCI_BRIDGE_BUS_SUBORDINATE_SHIFT) & 0xff);

	pci_scan_bus(&nbus);
	return 1;
}

#if 0
#define PCI_FIND_CAP_TTL	48

static int __pci_find_next_cap_ttl(struct pci_bus *bus,
				   u8 pos, int cap, int *ttl)
{
	u8 id;

	while ((*ttl)--) {
		pos = pci_conf_read(bus, pos, 1);
		if (pos < 0x40)
			break;
		pos &= ~3;
		id = pci_bus_read_config_byte(bus, pos + PCI_CAP_LIST_ID, 1);
		if (id == 0xff)
			break;
		if (id == cap)
			return pos;
		pos += PCI_CAP_LIST_NEXT;
	}
	return 0;
}

static int __pci_find_next_cap(struct pci_bus *bus, 
			       u8 pos, int cap)
{
	int ttl = PCI_FIND_CAP_TTL;

	return __pci_find_next_cap_ttl(bus, pos, cap, &ttl);
}

int pci_find_next_capability(struct pci_dev *dev, u8 pos, int cap)
{
	return __pci_find_next_cap(dev->bus, 
				   pos + PCI_CAP_LIST_NEXT, cap);
}

static int __pci_bus_find_cap_start(struct pci_bus *bus,
				    u8 hdr_type)
{
	u16 status;

	status = pci_conf_read_config_word(bus, PCI_STATUS, 2);
	if (!(status & PCI_STATUS_CAP_LIST))
		return 0;

	switch (hdr_type) {
	case PCI_HEADER_TYPE_NORMAL:
	case PCI_HEADER_TYPE_BRIDGE:
		return PCI_CAPABILITY_LIST;
	case PCI_HEADER_TYPE_CARDBUS:
		return PCI_CB_CAPABILITY_LIST;
	default:
		return 0;
	}

	return 0;
}

/**
 * pci_find_capability - query for devices' capabilities 
 * @dev: PCI device to query
 * @cap: capability code
 *
 * Tell if a device supports a given PCI capability.
 * Returns the address of the requested capability structure within the
 * device's PCI configuration space or 0 in case the device does not
 * support it.  Possible values for @cap:
 *
 *  %PCI_CAP_ID_PM           Power Management 
 *  %PCI_CAP_ID_AGP          Accelerated Graphics Port 
 *  %PCI_CAP_ID_VPD          Vital Product Data 
 *  %PCI_CAP_ID_SLOTID       Slot Identification 
 *  %PCI_CAP_ID_MSI          Message Signalled Interrupts
 *  %PCI_CAP_ID_CHSWP        CompactPCI HotSwap 
 *  %PCI_CAP_ID_PCIX         PCI-X
 *  %PCI_CAP_ID_EXP          PCI Express
 */
int pci_find_capability(struct pci_dev *dev, int cap)
{
	int pos;

	pos = __pci_bus_find_cap_start(dev->bus, dev->hdr_type);
	if (pos)
		pos = __pci_find_next_cap(dev->bus, pos, cap);

	return pos;
}
#endif

// External PCI subsystem interface

void pci_func_enable(struct pci_dev *f)
{
	pci_conf_write(f, PCI_COMMAND_STATUS_REG,
		       PCI_COMMAND_IO_ENABLE |
		       PCI_COMMAND_MEM_ENABLE |
		       PCI_COMMAND_MASTER_ENABLE, 3);

	u32 bar_width;
	u32 bar;

	for (bar = PCI_MAPREG_START; bar < PCI_MAPREG_END;
	     bar += bar_width)
	{
		u32 oldv = pci_conf_read(f, bar, 3);

		bar_width = 4;
		pci_conf_write(f, bar, 0xffffffff, 3);
		u32 rv = pci_conf_read(f, bar, 3);

		if (rv == 0)
			continue;

		int regnum = PCI_MAPREG_NUM(bar);
		u32 base, size;
		if (PCI_MAPREG_TYPE(rv) == PCI_MAPREG_TYPE_MEM) {
			if (PCI_MAPREG_MEM_TYPE(rv) == PCI_MAPREG_MEM_TYPE_64BIT)
				bar_width = 8;

			size = PCI_MAPREG_MEM_SIZE(rv);
			base = PCI_MAPREG_MEM_ADDR(oldv);
			if (pci_show_addrs)
				pr_debug("  mem region %d: %d bytes at 0x%x\n",
					regnum, size, base);
		} else {
			size = PCI_MAPREG_IO_SIZE(rv);
			base = PCI_MAPREG_IO_ADDR(oldv);
			if (pci_show_addrs)
				pr_debug("  io region %d: %d bytes at 0x%x\n",
					regnum, size, base);
		}

		pci_conf_write(f, bar, oldv, 3);
		f->reg_base[regnum] = base;
		f->reg_size[regnum] = size;

		if (size && !base)
			pr_debug("PCI device %02x:%02x.%d (%04x:%04x) "
				"may be misconfigured: "
				"region %d: base 0x%x, size %d\n",
				f->bus->busno, f->dev, f->func,
				PCI_VENDOR(f->dev_id), PCI_PRODUCT(f->dev_id),
				regnum, base, size);
	}

	pr_debug("PCI function %02x:%02x.%d (%04x:%04x) enabled\n",
		f->bus->busno, f->dev, f->func,
		PCI_VENDOR(f->dev_id), PCI_PRODUCT(f->dev_id));
}

int pci_init(void)
{
	int ret;
	static struct pci_bus root_bus;
	memset(&root_bus, 0, sizeof(root_bus));

	ret = pci_scan_bus(&root_bus);

	pr_debug("done pci_init\n");
	return ret;
}

