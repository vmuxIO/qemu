#include "qemu/osdep.h"
#include "sysemu/kvm.h"
#include "linux/kvm.h"

#include "qapi/error.h"
#include "monitor/monitor.h"
#include "io/channel.h"
#include "hw/sysbus.h"
#include "hw/virtio/virtio-mmio.h"
#include "hw/pci/pci.h"
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
