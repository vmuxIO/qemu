#ifndef IOREGIONFD_H
#define IOREGIONFD_H

#include <stdint.h>
#include <stdbool.h>

#include "exec/hwaddr.h"
#include "qemu/typedefs.h"
#include "io/channel.h"

// TODO maybe it would be prudent to include virtio in the struct and
// function names to make them clearly distinguishable from the ones of
// hw/remote
typedef struct {
    int kvmfd;
    int devfd;
    gpointer opaque;
    uint64_t offset;
    uint32_t size;
    QIOChannel *ioc;
    AioContext *ctx;
} IORegionFD;

// generic virtio read and write function types
typedef uint64_t (*mr_read_func)(void *opaque, hwaddr addr, unsigned size);
typedef void (*mr_write_func)(void *opaque, hwaddr addr, uint64_t value,
                              unsigned size);

// generic virtio ioregionfd handler function type
typedef void (*ioregionfd_handler)(void *opaque);

// this function handles ioregionfd reads and write for both virtio-mmio and
// the different memory regions of virtio-pci
int virtio_ioregionfd_qio_channel_read(IORegionFD *ioregfd,
                                       mr_read_func read_func,
                                       mr_write_func write_func,
                                       Error **errp);

// setup functions
int virtio_ioregionfd_channel_setup(IORegionFD *ioregfd,
                                    Error **errp);
int virtio_ioregionfd_init(IORegionFD *ioregfd,
                           gpointer opaque,
                           MemoryRegion *mr,
                           uint64_t offset,
                           uint32_t size,
                           bool posted_writes,
                           ioregionfd_handler handler);

#endif /* ifndef IOREGIONFD_H */
