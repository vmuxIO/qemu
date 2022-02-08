/*
 * Ioregionfd headers
 *
 * Copyright © 2018, 2022 Oracle and/or its affiliates.
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

#endif /* IOREGIONFD_H */
