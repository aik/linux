# !/bin/sh

set -x

cat ~/linux-marvell/arch/arm/boot/zImage  ~/linux-marvell/arch/arm/boot/dts/armada-375-wdmc-gen2-aik.dtb > ~/kernel-bin/zImage_and_dtb || exit
mkimage -A arm -O linux -T kernel -C none -a 0x00008000 -e 0x00008000 -n 'WDMC-Gen2' -d ~/kernel-bin/zImage_and_dtb ~/kernel-bin/uImage || exit
mkdir ~/usbbootstick/
sudo mount /dev/sdb1 ~/usbbootstick/
sudo cp ~/kernel-bin/uImage ~/usbbootstick/boot/ || exit
sync
sudo umount ~/usbbootstick/

