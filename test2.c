#include <stdint.h>
#include "bootrom_interfaces.h"

extern void platform_init();

/*_Noreturn*/ void c_entry() {
	//TODO warm-boot?
	//TODO 7885 does pshold set here when doing usb boot, this may be useful. Maybe we should do it no matter the soc whenever we get to an usb boot scenario.
	//TODO status bits?
	//TODO 7870 stock sets up some IRAM function ptrs. They don't seem to be neccessary for USB boot though...
	//7885 does a checksum check on bootrom here... we don't need that, but I'll just note it here
	//7885 also sets next stage address (and after loading, saves size and chksum in a different place)

	platform_init();

	//TODO support two boot devices, other boot devices, maybe save checksum, zero it out for signature check
	//Load BL31 from USB
	load_from_usb(0x02024000, 0x0206d000 - 0x02024000);
	//TODO verify BL31 (checksum and/or signature based on secureboot config)

	//TODO 7870 stock does PMIC init, though it doesn't seem to be required at least for USB boot...

	//Jump to BL31
	((void(*)())0x02024010)();
}
