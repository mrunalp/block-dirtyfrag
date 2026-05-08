#ifndef BLOCK_DIRTYFRAG_H
#define BLOCK_DIRTYFRAG_H

#ifndef __bpf__
#include <linux/types.h>
#endif

#define AF_RXRPC 33

#define BLOCK_REASON_RXRPC      1
#define BLOCK_REASON_XFRM       2
#define BLOCK_REASON_UDP_SPLICE 3

struct block_event {
	__u32 pid;
	char  comm[16];
	__u32 reason;
	__u64 ts;
};

#endif
