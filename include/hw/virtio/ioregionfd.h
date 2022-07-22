#ifndef IOREGIONFD_H
#define IOREGIONFD_H

// TODO maybe it would be prudent to include virtio in the struct and
// function names to make them clearly ditinguishable from the ones of
// hw/remote
typedef struct {
    int kvmfd;
    int devfd;
    uint64_t addr;
    uint32_t size;
    QIOChannel *ioc;
    AioContext *ctx;
} IORegionFD;


int virtio_qio_channel_ioregionfd_read(QIOChannel *ioc, gpointer opaque,
                                       Error **errp);

#endif /* ifndef IOREGIONFD_H */
