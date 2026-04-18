#include <stdint.h>

void platform_init() {
	//Force USB Boot! (TODO convert to modern boot config from old)
	*((uint32_t*)0x02020064) = 0xCB000442;
}
