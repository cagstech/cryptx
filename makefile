
include $(CEDEV)/meta/makefile.mk

#hashlib build rules
all: hashlib

hashlib: bin/HASHLIB.8xv

bin/HASHLIB.8xv: src/hashlib.asm
	$(call MKDIR,$(@D))
	fasmg src/hashlib.asm bin/HASHLIB.8xv

#make install
install: all
	$(CP) $(call NATIVEPATH,src/hashlib.h) $(call NATIVEPATH,$(CEDEV)/include)
	$(CP) $(call NATIVEPATH,bin/HASHLIB.lib) $(call NATIVEPATH,$(CEDEV)/lib/libload/hashlib.lib)

# make clean
# clean:
	# $(call RMDIR,bin)
	# $(Q)echo Removed binaries.

#make clean-install
clean-install:
	$(RM) $(call NATIVEPATH,$(CEDEV)/include/hashlib.h))
	$(RM) $(call NATIVEPATH,$(CEDEV)/lib/libload/hashlib.lib))

.PHONY: all install hashlib clean clean-install

.SECONDEXPANSION:
$(DIRS): $$(call DIRNAME,$$@)
	$(call MKDIR,$@)

