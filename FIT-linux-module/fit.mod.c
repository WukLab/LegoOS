#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x79833446, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x7aaabf54, __VMLINUX_SYMBOL_STR(alloc_pages_current) },
	{ 0xea645b46, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xadaabe1b, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0x63ae4981, __VMLINUX_SYMBOL_STR(ib_destroy_qp) },
	{ 0xeae3dfd6, __VMLINUX_SYMBOL_STR(__const_udelay) },
	{ 0x236437f6, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x343a1a8, __VMLINUX_SYMBOL_STR(__list_add) },
	{ 0x6c5b71ad, __VMLINUX_SYMBOL_STR(ib_modify_qp) },
	{ 0x18363747, __VMLINUX_SYMBOL_STR(ib_create_qp) },
	{ 0x8a6665c9, __VMLINUX_SYMBOL_STR(ib_alloc_pd) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x471dee83, __VMLINUX_SYMBOL_STR(ib_get_dma_mr) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0x68576186, __VMLINUX_SYMBOL_STR(ib_query_port) },
	{ 0x521445b, __VMLINUX_SYMBOL_STR(list_del) },
	{ 0xf11543ff, __VMLINUX_SYMBOL_STR(find_first_zero_bit) },
	{ 0xbcc82667, __VMLINUX_SYMBOL_STR(ib_register_client) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x1000e51, __VMLINUX_SYMBOL_STR(schedule) },
	{ 0x2c925659, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0xc497f84c, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x8deeaa85, __VMLINUX_SYMBOL_STR(ib_query_qp) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xfcb77f8a, __VMLINUX_SYMBOL_STR(ib_create_cq) },
	{ 0xf277f88e, __VMLINUX_SYMBOL_STR(ib_unregister_client) },
	{ 0x8bd4dfab, __VMLINUX_SYMBOL_STR(dma_ops) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core";


MODULE_INFO(srcversion, "9008C0AAAA6C9EC67351295");
