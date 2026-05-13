/* BPF LSM program to block DirtyFrag and Fragnesia exploits.
 *
 * Four layers of defense:
 *
 * 1. socket_create: Blocks AF_RXRPC socket creation globally —
 *    prevents the rxrpc/rxkad page-cache write path.
 *
 * 2. socket_sendmsg: Blocks MSG_SPLICE_PAGES on UDP sockets globally.
 *    Prevents splicing page-cache pages into a UDP socket where the
 *    ESP decryption engine would overwrite them in place.
 *    Only effective on kernel 6.4+ where MSG_SPLICE_PAGES exists.
 *
 * 3. tracepoint + socket_setsockopt: Blocks setsockopt(TCP_ULP,
 *    "espintcp") globally.  Prevents the Fragnesia ESP-in-TCP path.
 *    The tracepoint captures the optval string (not available to the
 *    LSM hook) so kTLS ("tls") is preserved.
 *
 * 4. socket_setsockopt: Blocks setsockopt(UDP_ENCAP) from non-init
 *    network namespaces.  Prevents DirtyFrag's ESP-in-UDP
 *    encapsulation setup from containers while allowing host-level
 *    IPsec/VPN.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "block_dirtyfrag.h"

/* CO-RE struct stubs — field names must match kernel BTF. */
struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

struct nsproxy {
	struct net *net_ns;
} __attribute__((preserve_access_index));

struct task_struct {
	struct nsproxy *nsproxy;
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

#define AF_INET            2
#define AF_INET6          10
#define SOCK_DGRAM         2
#define IPPROTO_TCP        6
#define IPPROTO_UDP       17
#define TCP_ULP           31
#define UDP_ENCAP        100
#define MSG_SPLICE_PAGES   0x08000000

/* Ring buffer for blocked-event notifications to userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

/*
 * Per-task flag set by the tracepoint when TCP_ULP "espintcp" is
 * detected.  The LSM hook reads and deletes it in the same syscall.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u8);
} espintcp_flag SEC(".maps");

/* Init net namespace inode number, populated by the userspace loader. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} init_net_ns SEC(".maps");

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

/* ---- Layer 1: block AF_RXRPC globally ---- */

SEC("lsm/socket_create")
int BPF_PROG(block_rxrpc, int family, int type, int protocol,
	     int kern, int ret)
{
	if (ret)
		return ret;

	if (kern)
		return 0;

	if (family == AF_RXRPC) {
		emit_event(BLOCK_REASON_RXRPC);
		return -EPERM;
	}

	return 0;
}

/* ---- Layer 2: block MSG_SPLICE_PAGES on UDP globally (6.4+) ---- */

SEC("lsm/socket_sendmsg")
int BPF_PROG(block_udp_splice, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	if (ret)
		return ret;

	if (!(msg->msg_flags & MSG_SPLICE_PAGES))
		return 0;

	if (sock->type != SOCK_DGRAM)
		return 0;

	struct sock *sk = sock->sk;
	if (!sk)
		return 0;

	__u16 family = sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	emit_event(BLOCK_REASON_UDP_SPLICE);
	return -EPERM;
}

/* ---- Layer 3: block TCP_ULP "espintcp" globally ---- */

/*
 * Tracepoint half: fires before the LSM hook in the same setsockopt
 * syscall.  Reads the optval from userspace and flags espintcp.
 */
struct setsockopt_args {
	__u64 __pad;
	__s32 __syscall_nr;
	__u32 __pad2;
	__u64 fd;
	__u64 level;
	__u64 optname;
	__u64 optval;
	__u64 optlen;
};

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int tp_setsockopt(struct setsockopt_args *ctx)
{
	if (ctx->level != IPPROTO_TCP || ctx->optname != TCP_ULP)
		return 0;

	char buf[16] = {};
	if (bpf_probe_read_user_str(buf, sizeof(buf),
				    (void *)ctx->optval) < 0)
		return 0;

	if (buf[0] != 'e' || buf[1] != 's' || buf[2] != 'p' ||
	    buf[3] != 'i' || buf[4] != 'n' || buf[5] != 't' ||
	    buf[6] != 'c' || buf[7] != 'p' || buf[8] != '\0')
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u8 flag = 1;
	bpf_map_update_elem(&espintcp_flag, &pid_tgid, &flag, BPF_ANY);
	return 0;
}

/*
 * LSM half: blocks the setsockopt if the tracepoint flagged espintcp.
 * Also handles Layer 4 (UDP_ENCAP from non-init net namespace).
 */
SEC("lsm/socket_setsockopt")
int BPF_PROG(block_setsockopt, struct socket *sock, int level,
	     int optname, int ret)
{
	if (ret)
		return ret;

	/* Layer 3: TCP_ULP espintcp — global block */
	if (level == IPPROTO_TCP && optname == TCP_ULP) {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		__u8 *flag = bpf_map_lookup_elem(&espintcp_flag, &pid_tgid);
		int is_espintcp = flag && *flag;
		bpf_map_delete_elem(&espintcp_flag, &pid_tgid);
		if (is_espintcp) {
			emit_event(BLOCK_REASON_ESPINTCP);
			return -EPERM;
		}
		return 0;
	}

	/* Layer 4: UDP_ENCAP — block from non-init net namespace */
	if (level == IPPROTO_UDP && optname == UDP_ENCAP) {
		__u32 key = 0;
		__u32 *init_inum = bpf_map_lookup_elem(&init_net_ns, &key);
		if (!init_inum)
			return 0;

		struct task_struct *task = bpf_get_current_task_btf();
		__u32 cur_inum = task->nsproxy->net_ns->ns.inum;
		if (cur_inum == *init_inum)
			return 0;

		emit_event(BLOCK_REASON_UDP_ENCAP);
		return -EPERM;
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
