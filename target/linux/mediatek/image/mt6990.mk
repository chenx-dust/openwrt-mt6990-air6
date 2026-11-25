define Build/lg6851f-android-boot
	python3 $(TOPDIR)/scripts/lg6851f_mkbootimg_v2.py \
		--meta $(TOPDIR)/target/linux/mediatek/image/lg6851f-boot-v2.json \
		--kernel $(KDIR)/Image \
		--dtb $(KDIR)/image-mt6990-fiberhome-lg6851f.dtb \
		--out $@
	cp -f $@ $(BIN_DIR)/boot_b.img
endef

# SPDX-License-Identifier: GPL-2.0-only
#
# MediaTek MT6990 / T830 devices

define Build/lg6851f-copy-rootfs-shortname
	cp -f $@ $(BIN_DIR)/rootfs_b.img
endef

define Device/fiberhome_lg6851f
  DEVICE_VENDOR := FiberHome
  DEVICE_MODEL := Pro LG6851F
  SOC := mt6990
  KERNEL_LOADADDR := 0x80080000
  KERNEL_ENTRY := 0x80080000
  DEVICE_DTS := mt6990-fiberhome-lg6851f
  DEVICE_DTS_DIR := ../dts
	DEVICE_PACKAGES := kmod-mt7996e kmod-mt7990-firmware luci-app-5gmodem luci-app-pwmfan \
	luci-theme-argon luci-theme-bootstrap \
	mt6990-adb-usb \
	kmod-mt6990-hwnat \
	libf2fs mkf2fs f2fsck
  IMAGES += boot_b.img rootfs_b.img
  IMAGE/boot_b.img := lg6851f-android-boot
  IMAGE/rootfs_b.img := append-rootfs | lg6851f-copy-rootfs-shortname
endef
TARGET_DEVICES += fiberhome_lg6851f

define Build/air6-android-boot
	python3 $(TOPDIR)/scripts/lg6851f_mkbootimg_v2.py \
		--meta $(TOPDIR)/target/linux/mediatek/image/air6-boot-v2.json \
		--kernel $(KDIR)/Image \
		--dtb $(KDIR)/image-mt6990-softbank-air6.dtb \
		--out $@
endef

define Build/air6-sign-boot
	python3 $(TOPDIR)/scripts/mt6990-sign-boot.py \
		--in $@ \
		--cert1 $(TOPDIR)/lg6851f_sign_tool/fg370-2305-opensdk/mtk/tools/common/security/config/mt2737/cert_config/sec_level_0/cert1/boot_cert1.der \
		--key $(TOPDIR)/lg6851f_sign_tool/fg370-2305-opensdk/mtk/tools/common/security/sign_master/hsm_test_keys/RSA2048/IMAGE_prvk.pem \
		--verify-root $(TOPDIR)/lg6851f_sign_tool/fg370-2305-opensdk/mtk/tools/common/security/sign_master/hsm_test_keys/RSA2048/ROOT_prvk.pem \
		--pad-size 33554432 \
		--out $@.signed
	mv -f $@.signed $@
	cp -f $@ $(BIN_DIR)/boot-verified.img
endef

define Build/air6-copy-rootfs
	cp -f $@ $(BIN_DIR)/rootfs.img
	sz=$$(stat -c '%s' $@); [ "$$sz" -le 134217728 ] || { echo "rootfs exceeds 128 MiB: $$sz" >&2; exit 1; }
	cp -f $@ $(BIN_DIR)/root.squashfs
	truncate -s 134217728 $(BIN_DIR)/root.squashfs
endef

define Device/softbank_air6
  DEVICE_VENDOR := SoftBank
  DEVICE_MODEL := Air 6
  SOC := mt6990
  KERNEL_LOADADDR := 0x80080000
  KERNEL_ENTRY := 0x80080000
  DEVICE_DTS := mt6990-softbank-air6
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-mt7996e kmod-mt7990-firmware lg6851f-modem-chain-only luci-app-5gmodem \
	kmod-mt6990-hwnat libf2fs mkf2fs f2fsck
  IMAGES += boot.img boot-verified.img rootfs.img
  IMAGE/boot.img := air6-android-boot
  IMAGE/boot-verified.img := air6-android-boot | air6-sign-boot
  IMAGE/rootfs.img := append-rootfs | air6-copy-rootfs
endef
TARGET_DEVICES += softbank_air6
