/* BPF LSM program to block DirtyFrag.
 *
 * A single socket_create hook blocks both exploit paths:
 *
 * 1. Blocks AF_RXRPC socket creation — prevents the rxrpc/rxkad
 *    page-cache write path entirely.
 *
 * 2. Blocks NETLINK_XFRM socket creation from containers — prevents
 *    the xfrm-ESP page-cache write path.  The check covers both:
 *    - Non-privileged containers: userns level > 0 (after unshare)
 *    - Privileged containers: pidns level > 0 (container PID namespace)
 *    Host-level IPsec/VPN (init userns + init pidns) is unaffected.
 *
 * Other networking is completely unaffected.
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

struct pid_namespace {
	unsigned int level;
} __attribute__((preserve_access_index));

struct cred___local {
	struct user_namespace *user_ns;
} __attribute__((preserve_access_index));

struct nsproxy___local {
	struct pid_namespace *pid_ns_for_children;
} __attribute__((preserve_access_index));

struct task_struct___local {
	const struct cred___local *cred;
	struct nsproxy___local *nsproxy;
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

	/* Block NETLINK_XFRM from containers (ESP path) */
	if (family != AF_NETLINK || protocol != NETLINK_XFRM)
		return 0;

	struct task_struct___local *task;
	int level;

	task = (void *)bpf_get_current_task();

	level = BPF_CORE_READ(task, cred, user_ns, level);
	if (level > 0)
		goto block_xfrm;

	level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
	if (level > 0)
		goto block_xfrm;

	return 0;

block_xfrm:
	emit_event(BLOCK_REASON_XFRM);
	return -1;
}

char LICENSE[] SEC("license") = "GPL";
