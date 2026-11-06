# SPDX-License-Identifier: MIT
#
# OpenWrt package for DongHoa. Builds from this source tree, not a tarball:
# add the repo's openwrt/ directory as a feed, e.g. in feeds.conf
#   src-link donghoa /path/to/repo/openwrt
# then: ./scripts/feeds update donghoa && ./scripts/feeds install donghoa

include $(TOPDIR)/rules.mk

PKG_NAME:=donghoa
PKG_VERSION:=1.0
PKG_RELEASE:=10
PKG_LICENSE:=MIT

# The feed is a symlink to <repo>/openwrt, and make's CURDIR is the
# physical path, so the source tree is two levels up.
DONGHOA_SRC_DIR ?= $(abspath $(CURDIR)/../..)

include $(INCLUDE_DIR)/package.mk

define Package/donghoa
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=WirelessAPD
  TITLE:=DongHoa: multi-AP roaming, band steering and load balancing (ARCP)
endef

define Package/donghoa/description
  DongHoa runs beside hostapd on every AP of an ESS and coordinates
  802.11k/v/r assisted roaming, band steering and load balancing with
  the other APs over ARCP, a Layer-2 protocol on EtherType 0x88B5.
endef

define Package/donghoa/conffiles
/etc/donghoa.conf
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(DONGHOA_SRC_DIR)/Makefile $(DONGHOA_SRC_DIR)/src $(DONGHOA_SRC_DIR)/tools \
		$(PKG_BUILD_DIR)/
endef

# C++17 without exceptions, RTTI or heap: the binaries link only libc
# (the top-level Makefile uses --as-needed), so no +libstdcpp dependency.
define Build/Compile
	cd $(PKG_BUILD_DIR) && \
		CXX="$(TARGET_CXX)" CXXFLAGS="$(TARGET_CXXFLAGS)" LDFLAGS="$(TARGET_LDFLAGS)" \
		$(MAKE) donghoa donghoa_cli
endef

define Package/donghoa/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/donghoa $(PKG_BUILD_DIR)/donghoa_cli $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/donghoa.init $(1)/etc/init.d/donghoa
	$(INSTALL_CONF) ./files/donghoa.conf $(1)/etc/donghoa.conf
endef

$(eval $(call BuildPackage,donghoa))
