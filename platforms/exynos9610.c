#include <stdint.h>

void platform_init() {
	//We need USB PHY FORCE_QACT
	*((uint32_t*)0x131d0004) = *((uint32_t*)0x131d0004) | 0x100;
}
