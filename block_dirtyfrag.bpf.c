/* BPF LSM program to block DirtyFrag.
 *
 * Two hooks block both exploit paths:
 *
 * 1. socket_create — blocks AF_RXRPC socket creation, preventing the
 *    rxrpc/rxkad page-cache write path entirely.
 *
 * 2. socket_create — blocks NETLINK_XFRM socket creation from non-init
 *    user namespaces (level > 0).  The ESP exploit must unshare into a
 *    new user namespace to gain CAP_NET_ADMIN, then create XFRM SAs
 *    via netlink.  Blocking NETLINK_XFRM at level > 0 prevents the
 *    exploit while allowing host-level IPsec/VPN (level 0) to work.
 *
 * Other networking (UDP, TCP, AF_ALG, AF_NETLINK for non-XFRM, etc.)
 * is completely unaffected.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "block_dirtyfrag.h"

/* CO-RE struct stubs — field names must match kernel BTF. */
struct user_namespace {
	int level;
} __attribute__((preserve_access_index));

struct cred___local {
	struct user_namespace *user_ns;
} __attribute__((preserve_access_index));

struct task_struct___local {
	const struct cred___local *cred;
} __attribute__((preserve_access_index));

#define AF_NETLINK   16
#define NETLINK_XFRM  6

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

static __always_inline void emit_event(__u32 reason)
{
	struct block_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (evt) {
		evt->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(evt->comm, sizeof(evt->comm));
		evt->reason = reason;
		evt->ts = bpf_ktime_get_ns();
		bpf_ringbuf_submit(evt, 0);
	}
}

SEC("lsm/socket_create")
int BPF_PROG(block_dirtyfrag, int family, int type, int protocol,
	     int kern, int ret)
{
	if (ret)
		return ret;

	/* Block AF_RXRPC sockets (rxrpc/rxkad path) */
	if (family == AF_RXRPC) {
		emit_event(BLOCK_REASON_RXRPC);
		return -EPERM;
	}

	/* Block NETLINK_XFRM from non-init user namespaces (ESP path) */
	if (family == AF_NETLINK && protocol == NETLINK_XFRM) {
		struct task_struct___local *task;
		int level;

		task = (void *)bpf_get_current_task();
		level = BPF_CORE_READ(task, cred, user_ns, level);

		if (level > 0) {
			emit_event(BLOCK_REASON_XFRM);
			return -EPERM;
		}
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
