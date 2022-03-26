/*
 * Ioregionfd headers
 *
 * Copyright © 2018, 2022 Oracle and/or its aggiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef IOREGIONFD_H
#define IOREGIONFD_H

#define PCI_BARS_NR 6

typedef struct {
    uint64_t val;
    bool memory;
} IORegionFDOp;

typedef struct {
    int fd;
    char *devid;
    uint32_t bar;
    uint32_t start;
    uint32_t size;
    bool memory;
} IORegionFD;

struct IORegionFDObject {
    /* private */
    Object parent;

    IORegionFD ioregfd;
    QTAILQ_ENTRY(IORegionFDObject) next;
};

typedef struct IORegionFDObject IORegionFDObject;

GSList *ioregionfd_get_obj_list(void);
IORegionFD *ioregionfd_get_by_bar(GSList *list, uint32_t bar);
void ioregionfd_set_bar_type(GSList *list, uint32_t bar, bool memory);
int qio_channel_ioregionfd_read(QIOChannel *ioc, gpointer opaque,
                                Error **errp);

#endif /* IOREGIONFD_H */
