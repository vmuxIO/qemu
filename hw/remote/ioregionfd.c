/*
 * Memory manager for remote device
 *
 * Copyright © 2018, 2021 Oracle and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
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
        error_setg(errp, "BAR start %"PRId64" is too big", value);
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
