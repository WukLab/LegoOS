# target monitor modules
MONITORS := gmm
MONITORS += gpm
MONITORS += gum
MONITORS += gm_dispatcher

# rules
SUBDIRS := $(addprefix $(shell pwd)/, $(MONITORS))
CLEAN_SUBDIRS := $(addsuffix .clean, $(SUBDIRS))

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

clean: $(CLEAN_SUBDIRS)
$(CLEAN_SUBDIRS):
	$(MAKE) -C $(basename $@) clean

install:
	insmod $(shell pwd)/gmm/lego_gmm.ko && \
	insmod $(shell pwd)/gpm/lego_gpm.ko && \
	insmod $(shell pwd)/gum/lego_gum.ko && \
	insmod $(shell pwd)/gm_dispatcher/lego_gm_dispatcher.ko

.PHONY: all $(SUBDIRS) $(CLEAN_SUBDIRS) install
