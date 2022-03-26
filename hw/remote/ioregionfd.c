/*
 * Memory manager for remote device
 *
 * Copyright © 2018, 2022 Oracle and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU FPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "sysemu/kvm.h"
#include "linux/kvm.h"

#include "exec/memory.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qom/object_interfaces.h"
#include "exec/confidential-guest-support.h"
#include "io/channel.h"
#include "qemu/sockets.h"
#include "qemu/cutils.h"
#include "io/channel-socket.h"
#include "monitor/monitor.h"
#include "hw/remote/ioregionfd.h"
#include "hw/pci/pci.h"
#include "qapi/qapi-visit-qom.h"
#include "hw/remote/remote.h"
#include "ioregionfd.h"

#define TYPE_IOREGIONFD_OBJECT "ioregionfd-object"
OBJECT_DECLARE_TYPE(IORegionFDObject, IORegionFDObjectClass, IOREGIONFD_OBJECT)

struct IORegionFDObjectClass {
    ObjectClass parent_class;

    unsigned int nr_ioregfds;
    unsigned int max_ioregfds;
};

static int ioregionfd_obj_list(Object *obj, void *opaque)
{
    GSList **list = opaque;

    if (object_dynamic_cast(obj, TYPE_IOREGIONFD_OBJECT)) {
        *list = g_slist_append(*list, obj);
    }

    object_child_foreach(obj, ioregionfd_obj_list, opaque);
    return 0;
}

/*
 * inquire ioregionfd objects and link them into the list which is
 * returned to the caller.
 *
 * Caller must free the list.
 */
GSList *ioregionfd_get_obj_list(void)
{
    GSList *list = NULL;

    object_child_foreach(object_get_root(), ioregionfd_obj_list, &list);
    return list;
}

IORegionFD *ioregionfd_get_by_bar(GSList *list, uint32_t bar)
{
    IORegionFDObject *ioregionfd;
    GSList *elem;

    for (elem = list; elem; elem = elem->next) {
        ioregionfd = elem->data; 

        if (ioregionfd->ioregfd.bar == bar) {
            return &ioregionfd->ioregfd;
        }
    }
    return NULL;
}

void ioregionfd_set_bar_type(GSList *list, uint32_t bar, bool memory)
{
    IORegionFDObject *ioregionfd;
    GSList *elem;

    for (elem = list; elem; elem = elem->next) {
        ioregionfd = elem->data; 
        if (ioregionfd->ioregfd.bar == bar) {
            ioregionfd->ioregfd.memory = memory;
        }
    }
}

int qio_channel_ioregionfd_read(QIOChannel *ioc, gpointer opaque,
                                Error **errp)
{
    struct RemoteObject *o = (struct RemoteObject *)opaque;
    struct ioregionfd_cmd cmd = {};
    struct iovec iov = {
        .iov_base = &cmd,
        .iov_len = sizeof(struct ioregionfd_cmd),
    };
    IORegionFDObject *ioregfd_obj;
    PCIDevice *pci_dev;
    hwaddr addr;
    struct ioregionfd_resp resp = {};
    int bar = 0;
    Error *local_err = NULL;
    uint64_t val = UINT64_MAX;
    AddressSpace *as;
    int ret = -EINVAL;

    ERRP_GUARD();

    if (!ioc) {
        return -EINVAL;
    }
    ret = qio_channel_readv_full(ioc, &iov, 1, NULL, 0, &local_err);

    if (ret == QIO_CHANNEL_ERR_BLOCK) {
        return -EINVAL;
    }

    if (ret <= 0) {
        /* read error or other side closed connection */
        if (local_err) {
            error_report_err(local_err);
        }
        error_setg(errp, "ioregionfd receive error");
        return -EINVAL;
    }

    bar = cmd.user_data;
    pci_dev = PCI_DEVICE(o->dev);
    addr = (hwaddr)(pci_get_bar_addr(pci_dev, bar) + cmd.offset);
    IORegionFDObject key = {.ioregfd = {.bar = bar} };
    ioregfd_obj = g_hash_table_lookup(o->ioregionfd_hash, &key);

    if (!ioregfd_obj) {
        error_setg(errp, "Could not find IORegionFDObject");
        return -EINVAL;
    }
    if (ioregfd_obj->ioregfd.memory) {
        as = &address_space_memory;
    } else {
        as = &address_space_io;
    }

    if (ret > 0 && pci_dev) {
        switch (cmd.cmd) {
        case IOREGIONFD_CMD_READ:
            ret = address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED,
                                   (void *)&val, 1 << cmd.size_exponent,
                                   false);
            if (ret != MEMTX_OK) {
                ret = -EINVAL;
                error_setg(errp, "Bad address %"PRIx64" in mem read", addr);
                val = UINT64_MAX;
            }

            memset(&resp, 0, sizeof(resp));
            resp.data = val;
            if (qio_channel_write_all(ioc, (char *)&resp, sizeof(resp),
                                      &local_err)) {
                error_propagate(errp, local_err); 
                goto fatal;
            }
            break;
        case IOREGIONFD_CMD_WRITE:
            ret = address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED,
                                   (void *)&cmd.data, 1 << cmd.size_exponent,
                                   true);
            if (ret != MEMTX_OK) {
                error_setg(errp, "Bad address %"PRIx64" for mem write", addr);
                val = UINT64_MAX;
            }

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
    }
    return ret;

fatal:
    return -EINVAL;
}

static void ioregionfd_object_init(Object *obj)
{
    IORegionFDObjectClass *k = IOREGIONFD_OBJECT_GET_CLASS(obj);

    if (k->nr_ioregfds >= k->max_ioregfds) {
        error_report("Reached max number of ioregions: %u", k->max_ioregfds);
        return;
    }
}

static void ioregionfd_object_set_fd(Object *obj, const char *str,
                                     Error **errp)
{
    IORegionFDObject *o = IOREGIONFD_OBJECT(obj);
    int fd = -1;

    fd = monitor_fd_param(monitor_cur(), str, errp);
    if (fd == -1) {
        error_prepend(errp, "Could not parse ioregionfd fd %s:", str);
        return;
    }
    o->ioregfd.fd = fd;
}

static void ioregionfd_object_set_devid(Object *obj, const char *str,
                                        Error **errp)
{
    IORegionFDObject *o = IOREGIONFD_OBJECT(obj);

    g_free(o->ioregfd.devid);

    o->ioregfd.devid = g_strdup(str);
}

static char *ioregionfd_object_get_devid(Object *obj, Error **errp)
{
    IORegionFDObject *o = IOREGIONFD_OBJECT(obj);

    return g_strdup(o->ioregfd.devid);
}

static void ioregionfd_object_set_bar(Object *obj, Visitor *v,
                                      const char *name, void *opaque,
                                      Error **errp)
{
    IORegionFDObject *o = IOREGIONFD_OBJECT(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }

    if (value > PCI_BARS_NR) {
        error_setg(errp, "BAR number cannot be larger than %d", PCI_BARS_NR);
        return;
    }

    o->ioregfd.bar = value;
}

static void ioregionfd_object_set_start(Object *obj, Visitor *v,
                                        const char *name, void *opaque,
                                        Error **errp)
{
    IORegionFDObject *o = IOREGIONFD_OBJECT(obj);
    int64_t value;

    if (!visit_type_int(v, name, &value, errp)) {
        return;
    }

    if (value < 0) {
        error_setg(errp, "BAR start %"PRId64" must be > 0", value);
        return;
    }

    if (value > UINT32_MAX) {
        error_setg(errp, "BAR start %"PRIx64" is too big", value);
        o->ioregfd.start = 0;
        return;
    }
    
    o->ioregfd.start = value;
}

static void ioregionfd_object_set_size(Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    IORegionFDObject *o = IOREGIONFD_OBJECT(obj);
    int64_t value;

    if (!visit_type_int(v, name, &value, errp)) {
        return;
    }
    
    if (value < 0) {
        error_setg(errp, "Invalid BAR size %"PRId64, value);
        return;
    }
    
    if (value > UINT32_MAX) {
        error_setg(errp, "BAR size %"PRId64" is too big", value);
        o->ioregfd.size = 0;
        return;
    }


    o->ioregfd.size = value;
}

static void ioregionfd_object_class_init(ObjectClass *klass, void *data)
{
    IORegionFDObjectClass *k = IOREGIONFD_OBJECT_CLASS(klass);

    k->nr_ioregfds = 0;
    k->max_ioregfds = 1;

    object_class_property_add_str(klass, "devid", ioregionfd_object_get_devid,
                                  ioregionfd_object_set_devid);
    object_class_property_add_str(klass, "iofd", NULL,
                                  ioregionfd_object_set_fd);
    object_class_property_add(klass, "bar", "uint32", NULL,
                              ioregionfd_object_set_bar, NULL, NULL);
    object_class_property_add(klass, "start", "uint64", NULL,
                              ioregionfd_object_set_start, NULL, NULL);
    object_class_property_add(klass, "size", "uint64", NULL,
                              ioregionfd_object_set_size, NULL, NULL);
}

/* Assume that Object user released all allocated structures. */
static void ioregionfd_object_finalize(Object *obj)
{
    IORegionFDObject *o = IOREGIONFD_OBJECT(obj);
    g_free(o->ioregfd.devid);
}

static const TypeInfo ioregionfd_object_info = {
    .name = TYPE_IOREGIONFD_OBJECT,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(IORegionFDObject),
    .instance_init = ioregionfd_object_init,
    .instance_finalize = ioregionfd_object_finalize,
    .class_size = sizeof(IORegionFDObjectClass),
    .class_init = ioregionfd_object_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void register_types(void)
{
    type_register_static(&ioregionfd_object_info);
}

type_init(register_types);
