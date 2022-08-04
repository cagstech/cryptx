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

include $(shell cedev-config --makefile)
