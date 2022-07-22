#include "qemu/osdep.h"
#include "sysemu/kvm.h"
#include "linux/kvm.h"

#include "qapi/error.h"
#include "monitor/monitor.h"
#include "io/channel.h"
#include "hw/sysbus.h"
#include "hw/virtio/virtio-mmio.h"
#include "hw/pci/pci.h"

#include "hw/virtio/ioregionfd.h"
#include "ioregionfd.h"


int virtio_qio_channel_ioregionfd_read(QIOChannel *ioc, gpointer opaque,
                                       Error **errp)
{
    struct VirtIOMMIOProxy *proxy = (struct VirtIOMMIOProxy *)opaque;
    struct ioregionfd_cmd cmd = {};
    struct iovec iov = {
        .iov_base = &cmd,
        .iov_len = sizeof(struct ioregionfd_cmd),
    };
    struct ioregionfd_resp resp = {};
    // variant 1
    // hwaddr addr;
    // AddressSpace *as;
    uint64_t val = UINT64_MAX;
    Error *local_err = NULL;
    int ret = -EINVAL;

    if (!ioc) {
        return -EINVAL;
    }
    ret = qio_channel_readv_full(ioc, &iov, 1, NULL, 0, &local_err);

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

    // variant 1
    // addr = (hwaddr) proxy->iomem.addr + 0x200 - 64 + cmd.offset;
    // as = &address_space_memory;

    switch (cmd.cmd) {
    case IOREGIONFD_CMD_READ:
        // variant 1
        // ret = address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED,
        //                        (void *)&val, 1 << cmd.size_exponent,
        //                        false);
        // if (ret != MEMTX_OK) {
        //     ret = -EINVAL;
        //     error_setg(errp, "Bad address %"PRIx64" in mem read", addr);
        //     val = UINT64_MAX;
        // }

        // variant 2
        val = virtio_mmio_read(proxy, cmd.offset, 1 << cmd.size_exponent);

        memset(&resp, 0, sizeof(resp));
        resp.data = val;
        if (qio_channel_write_all(ioc, (char *)&resp, sizeof(resp),
                                  &local_err)) {
            error_propagate(errp, local_err);
            goto fatal;
        }
        break;
    case IOREGIONFD_CMD_WRITE:
        // variant 1
        // ret = address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED,
        //                        (void *)&cmd.data, 1 << cmd.size_exponent,
        //                        true);
        // if (ret != MEMTX_OK) {
        //     error_setg(errp, "Bad address %"PRIx64" for mem write", addr);
        //     val = UINT64_MAX;
        // }

        // variant 2
        virtio_mmio_write(proxy, cmd.offset, cmd.data, 1 << cmd.size_exponent);
        ret = MEMTX_OK;

        if (cmd.resp) {
            memset(&resp, 0, sizeof(resp));
            if (ret != MEMTX_OK) {
                resp.data = UINT64_MAX;
                ret = -EINVAL;
            } else {
                resp.data = cmd.data;
            }
            if (qio_channel_write_all(ioc, (char *)&resp, sizeof(resp),
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
