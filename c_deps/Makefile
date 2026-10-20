######################################################################
# GNU Makefile for libsodium deps
######################################################################
LIBSODIUM_DIR ?= libsodium
LIBTOOLIZE ?= libtoolize
ACLOCAL ?= aclocal
AUTOMAKE ?= automake
AUTOCONF ?= autoconf

.PHONY += all
all: $(LIBSODIUM_DIR)/src/libsodium/.libs/libsodium.so

$(LIBSODIUM_DIR):
	git submodule update --force --checkout $(LIBSODIUM_DIR)

$(LIBSODIUM_DIR)/autogen.sh:
	git submodule update --force --checkout $(LIBSODIUM_DIR)

$(LIBSODIUM_DIR)/configure: $(LIBSODIUM_DIR) $(LIBSODIUM_DIR)/autogen.sh
	cd $(LIBSODIUM_DIR) \
		&& $(LIBTOOLIZE) --copy --install \
		&& $(ACLOCAL) \
		&& $(AUTOMAKE) --add-missing --copy --force-missing --include-deps \
		&& $(AUTOCONF)

$(LIBSODIUM_DIR)/Makefile: $(LIBSODIUM_DIR)/configure
	cd $(LIBSODIUM_DIR) \
		&& ./configure

$(LIBSODIUM_DIR)/src/libsodium/.libs/libsodium.so: $(LIBSODIUM_DIR)/Makefile
	cd $(LIBSODIUM_DIR) \
		&& make \
		&& make check

.PHONY: $(.PHONY)
