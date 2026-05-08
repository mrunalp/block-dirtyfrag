/* BPF LSM program to block DirtyFrag.
 *
 * Three layers of defense:
 *
 * 1. socket_create: Blocks AF_RXRPC socket creation — prevents the
 *    rxrpc/rxkad page-cache write path entirely.
 *
 * 2. socket_create: Blocks NETLINK_XFRM socket creation from
 *    containers — prevents the xfrm-ESP page-cache write path.
 *    The check covers both:
 *    - Non-privileged containers: userns level > 0 (after unshare)
 *    - Privileged containers: pidns level > 0 (container PID namespace)
 *    Host-level IPsec/VPN (init userns + init pidns) is unaffected.
 *
 * 3. socket_sendmsg: Blocks MSG_SPLICE_PAGES on UDP sockets globally.
 *    This is the actual dangerous primitive — splicing page-cache pages
 *    into a UDP socket lets the ESP decryption engine overwrite them
 *    in place.  Normal UDP send/sendmsg (without splice) is unaffected.
 *    No legitimate IPsec implementation uses splice-to-UDP.
 *    This layer closes the gap where a container with hostPID +
 *    hostNetwork + CAP_NET_ADMIN bypasses both namespace checks.
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

struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr {
	unsigned int msg_flags;
} __attribute__((preserve_access_index));

#define AF_NETLINK        16
#define AF_INET            2
#define AF_INET6          10
#define NETLINK_XFRM       6
#define SOCK_DGRAM         2
#define MSG_SPLICE_PAGES   0x08000000

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

/* Layer 3: block MSG_SPLICE_PAGES on UDP sockets globally.
 * Catches the dangerous primitive regardless of how CAP_NET_ADMIN was obtained.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(block_udp_splice, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	if (ret)
		return ret;

	if (!(BPF_CORE_READ(msg, msg_flags) & MSG_SPLICE_PAGES))
		return 0;

	if (BPF_CORE_READ(sock, type) != SOCK_DGRAM)
		return 0;

	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	emit_event(BLOCK_REASON_UDP_SPLICE);
	return -1;
}

char LICENSE[] SEC("license") = "GPL";
