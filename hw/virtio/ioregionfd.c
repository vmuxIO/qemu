#include <stdint.h>
#include <stdbool.h>

#include "qemu/typedefs.h"
#include "qemu/osdep.h"
#include "sysemu/iothread.h"
#include "sysemu/kvm.h"
#include "linux/kvm.h"

#include "qapi/error.h"
#include "monitor/monitor.h"
#include "hw/sysbus.h"
#include "hw/virtio/virtio-mmio.h"
#include "hw/pci/pci.h"
#include "io/channel-util.h"
#include "io/channel.h"
// #include "hw/virtio/virtio-pci.h"

#include "hw/virtio/ioregionfd.h"
#include "ioregionfd.h"


int virtio_ioregionfd_qio_channel_read(IORegionFD *ioregfd,
                                       mr_read_func read_func,
                                       mr_write_func write_func,
                                       Error **errp)
{
    struct ioregionfd_cmd cmd = {};
    struct iovec iov = {
        .iov_base = &cmd,
        .iov_len = sizeof(struct ioregionfd_cmd),
    };
    struct ioregionfd_resp resp = {};
    uint64_t val = UINT64_MAX;
    Error *local_err = NULL;
    int ret = -EINVAL;

    if (!ioregfd->ioc) {
        return -EINVAL;
    }
    ret = qio_channel_readv_full(ioregfd->ioc, &iov, 1, NULL, 0, &local_err);

    if (ret == QIO_CHANNEL_ERR_BLOCK) {
        return -EINVAL;
    }

    if (ret <= 0) {
        if (local_err) {
            error_report_err(local_err);
        }
        error_setg(errp, "ioregionfd receive error");
        return -EINVAL;
    }

    switch (cmd.cmd) {
    case IOREGIONFD_CMD_READ:
        val = read_func(ioregfd->opaque, ioregfd->offset + cmd.offset,
                        1 << cmd.size_exponent);

        memset(&resp, 0, sizeof(resp));
        resp.data = val;
        if (qio_channel_write_all(ioregfd->ioc, (char *)&resp, sizeof(resp),
                                  &local_err)) {
            error_propagate(errp, local_err);
            goto fatal;
        }
        break;
    case IOREGIONFD_CMD_WRITE:
        write_func(ioregfd->opaque, ioregfd->offset + cmd.offset, cmd.data,
                   1 << cmd.size_exponent);
        ret = MEMTX_OK;

        if (cmd.resp) {
            memset(&resp, 0, sizeof(resp));
            if (ret != MEMTX_OK) {
                resp.data = UINT64_MAX;
                ret = -EINVAL;
            } else {
                resp.data = cmd.data;
            }
            if (qio_channel_write_all(ioregfd->ioc, (char *)&resp, sizeof(resp),
                                      &local_err)) {
                error_propagate(errp, local_err);
                goto fatal;
            }
        }
        break;
    default:
        error_setg(errp, "Unknown ioregionfd command from kvm");
        break;
    }

fatal:
    return ret;
}

static IOThread *ioregionfd_iot;

int virtio_ioregionfd_channel_setup(IORegionFD *ioregfd,
                                    Error **errp)
{
    int ret = -1;
    int fds[2] = {-1, -1};

    // create fds from socketpair
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds) < 0) {
        error_prepend(errp, "Could not create socketpair for ioregionfd");
        error_report_err(*errp);
        goto fatal;
    }
    ioregfd->kvmfd = fds[0];
    ioregfd->devfd = fds[1];

    // create io channel
    if (!(ioregfd->ioc = qio_channel_new_fd(ioregfd->devfd, errp))) {
        error_prepend(errp, "Could not create IOC channel for" \
                      "ioregionfd fd %d.", ioregfd->devfd);
        error_report_err(*errp);
        goto fatal;
    }

    // create io thread
    if (ioregionfd_iot == NULL) {
        ioregionfd_iot = iothread_create("virtio ioregionfd iothread", errp);
        if (*errp) {
            qio_channel_shutdown(ioregfd->ioc, QIO_CHANNEL_SHUTDOWN_BOTH,
                                 NULL);
            qio_channel_close(ioregfd->ioc, NULL);
            error_report_err(*errp);
            goto fatal;
        }
    }

    // get aio context
    ioregfd->ctx = iothread_get_aio_context(ioregionfd_iot);

    ret = 0;
fatal:
    return ret;
}

extern const MemoryRegionOps unassigned_mem_ops;

int virtio_ioregionfd_init(IORegionFD *ioregfd,
                           gpointer opaque,
                           MemoryRegion *mr,
                           uint64_t offset,
                           uint32_t size,
                           ioregionfd_handler handler)
{
    struct kvm_ioregion ioregion;
    Error *local_error = NULL;
    int ret = -1;

    // setup the io channel
    if (virtio_ioregionfd_channel_setup(ioregfd, &local_error)) {
        error_prepend(&local_error, "Could not setup ioregionfd channel.");
        error_report_err(local_error);
        goto fatal;
    }

    // initialize the rest of the local ioregionfd struct
    ioregfd->opaque = opaque;
    ioregfd->offset = offset;
    ioregfd->size = size;

    // register io channel handler
    qio_channel_set_aio_fd_handler(ioregfd->ioc, 
                                   ioregfd->ctx,
                                   handler,
                                   NULL,
                                   ioregfd);

    // initialize ioregion kernel struct
    ioregion.guest_paddr = mr->addr + offset;
    ioregion.memory_size = size;
    ioregion.user_data = 0;
    ioregion.read_fd = ioregfd->kvmfd;
    ioregion.write_fd = ioregfd->kvmfd;
    ioregion.flags = 0;
    memset(&ioregion.pad, 0, sizeof(ioregion.pad));

    // register ioregion with kvm
    if (kvm_set_ioregionfd(&ioregion)) {
        error_setg(&local_error, "Could not register ioregionfd");
        goto fatal;
    }

    // remove memops if entire region is handled by ioregionfd
    if (offset == 0 && size == mr->size) {
       mr->ops = &unassigned_mem_ops;
    }

    ret = 0;
fatal:
    return ret;
}
