/*
 * RemoteObject header.
 *
 * Copyright © 2018, 2022 Oracle and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#ifndef REMOTE_H
#define REMOTE_H

struct RemoteObject {
    /* private */
    Object parent;

    Notifier machine_done;

    int32_t fd;
    char *devid;

    QIOChannel *ioc;

    DeviceState *dev;
    DeviceListener listener;
};

#endif
