# OpenExyBootchain
This project aims to be an open-source replacement to Samsung's bootchain on Exynos devices. It aims to be compatible with the existing bootchain (with induvidual parts being replacable), while also providing useful features.

## How can I use this?
You can
- Boot temporarily using [an exploit in Exynos EUB mode](https://github.com/VDavid003/exynos-usbdl)
- Boot permanently by fusing your own (or a community) secure boot key in the SoC (This is actually possible on retail devices as long as at least one of the key banks are unused and not permanently disabled, which seems true for most devices!)
- Boot permanently on an unfused SoC, or maybe using some tricks to "re-fuse" it into disabling secure boot (Theoretically might be possible by blowing more efuse bits).
- Write an emulator I guess?

## Why? Why not just use U-Boot/LK/any other bootloader?
Mostly for research purposes. I think an open source boot stack that can still boot stock software is helpful for security research, and just generally having fun with the existing software. It could be used for various things, like
- Researching/documenting stock EL3 monitor/TEE/Hypervisor, trying to find vulnerabilities in them
- Porting custom/existing TEE/EL3 monitor/Hypervisors without replacing anything unneccessary
- Bypassing FRP, or any other obstacle preventing you from using a device you legally own
- Maybe (temporarily or permanently) unlocking the bootloader of some devices that have a non-unlockable bootloader (from factory, or later locked via updates)?
- Getting some use out of devices with a dead eMMC/UFS by booting them off of an SD card
- You tell me :-)

## Status
Currently this project is still in very early stages, only BL1 exists, only (barely) supports USB booting, only supports secure boot, and currently only on 2 devices and SoCs:
- Samsung Galaxy A3 (2017) (Exynos7870)
- Samsung Galaxy A8 (2018) (Exynos7885)

In this state, there isn't that much you can do with it, other than experiment/research early boot.

## Building
The project uses the KConfig/KBuild system of the Linux kernel. I will later provide instructions on how to use it, but if you are familiar with that, then this project should work the same way, except that we currently need to generate/use signing keys for BL1, and need to include public keys for the stage after (extracted from stock boot stack, not included here).
