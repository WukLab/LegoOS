# target modules
MODULES := fit
MODULES += storage
MODULES += monitor

# rules
SUBDIRS := $(addprefix $(shell pwd)/, $(MODULES))
CLEAN_SUBDIRS := $(addsuffix .clean, $(SUBDIRS))

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

clean: $(CLEAN_SUBDIRS)
$(CLEAN_SUBDIRS):
	$(MAKE) -C $(basename $@) clean

fit_install:
	insmod $(shell pwd)/fit/fit.ko

storage_install:
	insmod $(shell pwd)/storage/storage.ko

monitor_install:
	$(MAKE) -C $(filter %monitor,$(SUBDIRS)) install

help:
	@echo	'Targets compilation:'
	@echo	' default		- Compile all linux modules'
	@echo	' clean			- remove all generated files'
	@echo	''
	@echo	'Modules install:'
	@echo	' fit_install		- insert fit module'
	@echo	' storage_install	- insert storage module'
	@echo	' monitor_install	- insert all monitor modules, including'
	@echo	'			  gpm, gmm, gum, and gm_dispatcher'

.PHONY: all $(SUBDIRS) $(CLEAN_SUBDIRS) fit_install \
	storage_install monitor_install help
