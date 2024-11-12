#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach/mach_traps.h>
#import <substrate.h>

/**
 * Developed by: DEVMUSTFA 
 * Instagram: @QIHB
 * Date: November 2021
 * Purpose: To protect games and applications from tampering and hacking.
 * 
 * WARNING: This code should be used with caution as it can cause unintended changes 
 * if applied incorrectly to applications or games.
 * 
 * License:
 * 
 * 1. This code is available for personal use only. 
 * 2. Redistribution or modification of this code for commercial purposes is strictly prohibited without prior permission from the author.
 * 3. The use of this code in any unauthorized, illegal, or malicious activities is not allowed. The author is not responsible for any damages or issues arising from misuse of the code.
 * 4. You may not sell, lease, or sublicense this code.
 * 5. Any use of this code in public repositories or projects should provide proper attribution to the original author (DEVMUSTFA, Instagram: @QIHB).
 * 
 * DISCLAIMER:
 * This software is provided "as-is" without any warranties, either expressed or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. 
 * In no event shall the author be held liable for any damages arising from the use or inability to use this software.
 */

BOOL isASLRActive() {
    const struct mach_header *header = _dyld_get_image_header(0);
    return (header->flags & MH_PIE) != 0;
}

uint64_t fetchSlide() {
    return _dyld_get_image_vmaddr_slide(0);
}

uint64_t computeRealAddress(uint64_t offset) {
    return isASLRActive() ? (fetchSlide() + offset) : offset;
}

BOOL needs32BitProcessing(uint32_t value) {
    uint32_t mask = value & 0xffff8000;
    uint32_t adjusted = mask + 0x00008000;
    return (adjusted & 0xffff7fff) != 0;
}

BOOL modifyMemory(uint64_t offset, uint32_t data) {
    kern_return_t status;
    mach_port_t currentTask = mach_task_self();
    uint64_t targetAddress = computeRealAddress(offset);

    status = vm_protect(currentTask, targetAddress, sizeof(data), NO, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (status != KERN_SUCCESS) return NO;

    if (needs32BitProcessing(data)) {
        data = CFSwapInt32(data);
        status = vm_write(currentTask, targetAddress, (vm_address_t)&data, sizeof(data));
    } else {
        uint16_t shortData = (uint16_t)data;
        shortData = CFSwapInt16(shortData);
        status = vm_write(currentTask, targetAddress, (vm_address_t)&shortData, sizeof(shortData));
    }

    if (status != KERN_SUCCESS) return NO;

    status = vm_protect(currentTask, targetAddress, sizeof(data), NO, VM_PROT_READ | VM_PROT_EXECUTE);
    return (status == KERN_SUCCESS);
}
