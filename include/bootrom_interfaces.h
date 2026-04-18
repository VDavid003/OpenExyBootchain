#ifndef _BOOTROM_INTERFACES_H
#define _BOOTROM_INTERFACES_H

#include <stdint.h>
#include "socs.h"
#include SOC_HEADER(bootrom_interfaces.h)

#ifndef BOOTROM_LOAD_USB_CALL_NEEDS_SIZE //Below 7885, for example 7870
typedef uint32_t (*load_from_usb_ptr)(uint32_t load_addr);
#define load_from_usb(addr, size) ((load_from_usb_ptr)(uint64_t)(*((uint32_t*)(0x020200DC))))(addr)
#else //7885 and above
typedef uint32_t (*load_from_usb_ptr)(uint32_t load_addr, uint32_t max_size);
#define load_from_usb(addr, size) ((load_from_usb_ptr)(uint64_t)(*((uint32_t*)(0x020200DC))))(addr, size)
#endif

#endif /* _BOOTROM_INTERFACES_H */
