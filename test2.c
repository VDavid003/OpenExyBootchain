#include <stdint.h>

typedef uint32_t (*load_bl1_usb)(uint32_t load_addr);

/*_Noreturn*/ void c_entry() {
	//TODO warm-boot?
	//TODO status bits?
	//TODO 7870 stock sets up some IRAM function ptrs. They don't seem to be neccessary for USB boot though...

	//Force USB Boot!
	*((uint32_t*)0x02020064) = 0xCB000442;

	//TODO support two boot devices, other boot devices, maybe save checksum, zero it out for signature check
	//Load BL31 from USB
	load_bl1_usb asd = (void*)(uint64_t)(*((uint32_t*)(0x020200DC)));
	asd(0x02024000);

	//TODO verify BL31 (checksum and/or signature based on secureboot config)

	//TODO 7870 stock does PMIC init, though it doesn't seem to be required at least for USB boot...

	//Jump to BL31
	((void(*)())0x02024010)();
}
