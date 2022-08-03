# ----------------------------
# Makefile Options
# ----------------------------

NAME = HASHLIB
ICON = icon.png
DESCRIPTION = "TI-Trek Multiplayer"
COMPRESSED = NO
ARCHIVED = NO
HAS_PRINTF := NO
LTO = NO


CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

# ----------------------------

ifndef CEDEV
$(error CEDEV environment path variable is not set)
endif

include $(CEDEV)/meta/makefile.mk

uxassets.bin: $(GFXDIR)/uxassets.bin
$(GFXDIR)/uxassets.bin: $(GFXDIR)/uxassets.8xv
	$(CONVBIN) -i $(GFXDIR)/uxassets.8xv -o $(GFXDIR)/uxassets.bin -j 8x -k bin


#$(OBJDIR)/trekfont.src: $(SRCDIR)/trekfont.inc

# Convert a .fnt file into a .inc file
#$(SRCDIR)/trekfont.inc: $(SRCDIR)/trekfont.fnt
#    convfont -o carray -f $(SRCDIR)/trekfont.fnt $(SRCDIR)/trekfont.inc
