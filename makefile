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

LIB_SRC := hashlib/hashlib.asm cryptoc/cryptoc.asm
LIB_LIB := hashlib/hashlib.lib cryptoc/cryptoc.lib
LIB_8XV := hashlib/hashlib.8xv cryptoc/cryptoc.8xv
LIB_H   := hashlib/hashlib.h cryptoc/cryptoc.h
PKG_INC := -i hashlib/hashlib.8xv -i cryptoc/cryptoc.8xv

all: hashlib cryptoc

hashlib: hashlib/hashlib.8xv

cryptoc: cryptoc/cryptoc.8xv

hashlib/hashlib.8xv: hashlib/hashlib.asm
	sed -i '' 's/BB.*_/\.lbl_/g' hashlib/hashlib.asm
	$(Q)$(FASMG) $< $@

cryptoc/cryptoc.8xv: cryptoc/cryptoc.asm
	sed -i '' 's/BB.*_/\.lbl_/g' cryptoc/cryptoc.asm
	$(Q)$(FASMG) $< $@

clean:
	$(Q)$(call REMOVE,$(LIB_LIB) $(LIB_8XV))

install: all
	$(Q)$(call MKDIR,$(INSTALL_LIB))
	$(Q)$(call COPY,$(LIB_LIB),$(INSTALL_LIB))
	$(Q)$(call MKDIR,$(INSTALL_H))
	$(Q)$(call COPY,$(LIB_H),$(INSTALL_H))
	
package: all
	convbin $(PKG_INC) -j 8x -o cryptx.8xg -k 8xg -name CryptX

.PHONY: all clean install

