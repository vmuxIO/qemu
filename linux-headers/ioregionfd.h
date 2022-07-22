/* SPDX-License-Identifier: ((GPL-2.0-only WITH Linux-syscall-note) OR BSD-3-Clause) */
#ifndef _UAPI_LINUX_IOREGION_H
#define _UAPI_LINUX_IOREGION_H

/* Wire protocol */

struct ioregionfd_cmd {
	__u8 cmd : 4;
	__u8 size_exponent : 2;
	__u8 resp : 2;
	__u64 user_data;
	__u64 offset;
	__u64 data;
} __attribute__((packed));

struct ioregionfd_resp {
	__u64 data;
	__u8 pad[24];
};

#define IOREGIONFD_CMD_READ    0
#define IOREGIONFD_CMD_WRITE   1

#define IOREGIONFD_SIZE_8BIT   0
#define IOREGIONFD_SIZE_16BIT  1
#define IOREGIONFD_SIZE_32BIT  2
#define IOREGIONFD_SIZE_64BIT  3

#endif
