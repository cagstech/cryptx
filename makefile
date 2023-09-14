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

include ../common.mk

LIB_SRC			:= cryptx.asm
LIB_LIB			:= cryptx.lib
LIB_8XV			:= cryptx.8xv
LIB_H			:= cryptx.h
LIB_EXAMPLES	:= $(shell ls -d examples/*)

all: $(LIB_8XV)

$(LIB_8XV): $(LIB_SRC)
	$(Q)$(FASMG) $< $@

clean:
	$(Q)$(call REMOVE,$(LIB_LIB) $(LIB_8XV))

install: all
	$(Q)$(call MKDIR,$(INSTALL_LIB))
	$(Q)$(call MKDIR,$(INSTALL_H))
	$(Q)$(call COPY,$(LIB_LIB),$(INSTALL_LIB))
	$(Q)$(call COPY,$(LIB_H),$(INSTALL_H))

examples: $(LIB_EXAMPLES)
$(LIB_EXAMPLES):
	$(MAKE) clean -C $@
	$(MAKE) -C $@

archive: cryptx.zip
cryptx.zip:
	zip cryptx.zip README.md cryptx.8xv cryptx.lib cryptx.h cryptx.asm


.PHONY: all clean install examples archive $(LIB_EXAMPLES)
