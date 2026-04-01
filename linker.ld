/* =============================================================================
 * Kernel Zxyphor - Linker Script
 * =============================================================================
 * Memory layout for x86_64 higher-half kernel loaded by Multiboot2-compliant
 * bootloader. The kernel is mapped at the -2GB virtual address (0xFFFFFFFF80000000)
 * which is the standard higher-half kernel address on x86_64.
 *
 * Physical load address: 1MB (0x100000)
 * Virtual base address:  0xFFFFFFFF80000000
 * ========================================================================== */

ENTRY(_start)

/* Virtual address where the kernel will be mapped */
KERNEL_VMA = 0xFFFFFFFF80000000;

/* Physical address where the bootloader places us */
KERNEL_LMA = 0x100000;

SECTIONS
{
    /* -------------------------------------------------------------------
     * Start at physical address 1MB where GRUB loads us, but set VMA
     * to the higher-half virtual address
     * ---------------------------------------------------------------- */
    . = KERNEL_LMA;

    /* Store the physical start address for later use */
    __kernel_phys_start = .;

    /* -------------------------------------------------------------------
     * Multiboot header must be in the first 8KB of the binary.
     * This section is placed first to ensure the bootloader finds it.
     * ---------------------------------------------------------------- */
    .multiboot ALIGN(4K) :
    {
        KEEP(*(.multiboot))
    }

    /* -------------------------------------------------------------------
     * Bootstrap code that runs before paging is enabled.
     * This code sets up initial page tables and jumps to higher half.
     * ---------------------------------------------------------------- */
    .bootstrap ALIGN(4K) :
    {
        *(.bootstrap)
        *(.bootstrap.*)
    }

    /* -------------------------------------------------------------------
     * Initial page tables used during bootstrap.
     * These are identity-mapped and also map the higher-half.
     * ---------------------------------------------------------------- */
    .boot_page_tables ALIGN(4K) :
    {
        *(.boot_page_tables)
    }

    /* Switch to virtual addresses for the rest of the kernel */
    . += KERNEL_VMA;

    /* Store virtual start address */
    __kernel_virt_start = .;

    /* -------------------------------------------------------------------
     * Kernel text (code) section
     * Aligned to 4KB page boundary for proper page protection
     * ---------------------------------------------------------------- */
    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VMA)
    {
        __text_start = .;
        *(.text)
        *(.text.*)
        __text_end = .;
    }

    /* -------------------------------------------------------------------
     * Read-only data section
     * Contains constants, string literals, and other immutable data
     * ---------------------------------------------------------------- */
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VMA)
    {
        __rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        __rodata_end = .;
    }

    /* -------------------------------------------------------------------
     * Initialized data section
     * Contains global variables with initial values
     * ---------------------------------------------------------------- */
    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VMA)
    {
        __data_start = .;
        *(.data)
        *(.data.*)
        __data_end = .;
    }

    /* -------------------------------------------------------------------
     * BSS (Block Started by Symbol) section
     * Contains uninitialized global variables, zero-filled at boot
     * ---------------------------------------------------------------- */
    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VMA)
    {
        __bss_start = .;
        *(COMMON)
        *(.bss)
        *(.bss.*)
        __bss_end = .;
    }

    /* -------------------------------------------------------------------
     * Kernel stack
     * 64KB stack for the bootstrap processor (BSP)
     * ---------------------------------------------------------------- */
    .stack ALIGN(4K) : AT(ADDR(.stack) - KERNEL_VMA)
    {
        __stack_bottom = .;
        . += 64K;
        __stack_top = .;
    }

    /* Mark the end of the kernel image */
    __kernel_end = .;
    __kernel_phys_end = __kernel_end - KERNEL_VMA;

    /* -------------------------------------------------------------------
     * Compute kernel size for memory manager initialization
     * ---------------------------------------------------------------- */
    __kernel_size = __kernel_end - __kernel_virt_start;
    __kernel_phys_size = __kernel_phys_end - __kernel_phys_start;

    /* -------------------------------------------------------------------
     * Discard sections we don't need
     * ---------------------------------------------------------------- */
    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}
