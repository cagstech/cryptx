# Copyright (C) 2015-2020
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

include $(CURDIR)/../common.mk

LIBS := hashlib cryptoc encodex
TOOLS := fasmg convbin convimg convfont cedev-config


SRCDIR = $(call NATIVEPATH,$1)

all: $(LIBS)

hashlib: hashlib/hashlib.8xv
cryptoc: cryptoc/cryptoc.8xv
encodex: encodex/encodex.8xv

hashlib/hashlib.8xv: hashlib/hashlib.asm
	sed -i '' 's/BB.*_/\.lbl_/g' hashlib/hashlib.asm
	$(Q)$(FASMG) $< $@

cryptoc/cryptoc.8xv: cryptoc/cryptoc.asm
	sed -i '' 's/BB.*_/\.lbl_/g' cryptoc/cryptoc.asm
	$(Q)$(FASMG) $< $@
	
encodex/encodex.8xv: encodex/encodex.asm
	sed -i '' 's/BB.*_/\.lbl_/g' encodex/encodex.asm
	$(Q)$(FASMG) $< $@


clean:
	$(foreach library,$(LIBS),$(call REMOVE, $(call SRCDIR,$(library))/$(library).lib $(call SRCDIR,$(library))/$(library).8xv))

install: all
	$(Q)$(call MKDIR,$(INSTALL_LIB))
	$(Q)$(call MKDIR,$(INSTALL_H))
	cp hashlib/hashlib.lib $(INSTALL_LIB)
	cp cryptoc/cryptoc.lib $(INSTALL_LIB)
	cp encodex/encodex.lib $(INSTALL_LIB)
	cp hashlib/hashlib.h $(INSTALL_H)
	cp cryptoc/cryptoc.h $(INSTALL_H)
	cp encodex/encodex.h $(INSTALL_H)
	
group: $(LIBS)
	convbin --iformat 8x --oformat 8xg-auto-extract \
		$(foreach library,$(LIBS),$(addprefix --input ,$(call SRCDIR,$(library))/$(library).8xv)) --output $(call NATIVEPATH,CryptX.8xg)
	
check:
	$(Q)$(EZCC) --version || ( echo Please install ez80-clang && exit 1 )
	$(Q)$(FASMG) $(NULL) $(NULL) || ( echo Please install fasmg && exit 1 )

.PHONY: all clean install

