/* BPF LSM program to block DirtyFrag.
 *
 * Three hooks block both exploit paths:
 *
 * 1. socket_create — blocks AF_RXRPC socket creation, preventing the
 *    rxrpc/rxkad page-cache write path entirely.
 *
 * 2. socket_sendmsg — blocks MSG_SPLICE_PAGES sends on UDP sockets
 *    (kernel 6.5+).  The exploit splices page-cache pages into a UDP
 *    socket; the kernel sets MSG_SPLICE_PAGES for zero-copy sends.
 *    Normal sendmsg/write is unaffected.
 *
 * 3. socket_setsockopt — blocks setsockopt(SOL_UDP, UDP_ENCAP) as a
 *    fallback for pre-6.5 kernels where splice-to-socket uses the
 *    sendpage path instead of sendmsg+MSG_SPLICE_PAGES.
 *
 * Other networking (TCP, AF_ALG, AF_NETLINK, etc.) is unaffected.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "block_dirtyfrag.h"

/* CO-RE struct stubs — field names must match kernel BTF.
 * Actual offsets are relocated at load time by libbpf. */
struct sock_common {
	__u16 skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr {
	unsigned int msg_flags;
} __attribute__((preserve_access_index));

#define AF_INET   2
#define AF_INET6 10
#define SOCK_DGRAM 2
#define IPPROTO_UDP 17
#define SOL_UDP    17
#define UDP_ENCAP  100
#define MSG_SPLICE_PAGES 0x08000000

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

/* Block AF_RXRPC sockets (rxrpc/rxkad path) */
SEC("lsm/socket_create")
int BPF_PROG(block_rxrpc, int family, int type, int protocol,
	     int kern, int ret)
{
	if (ret)
		return ret;

	if (family != AF_RXRPC)
		return 0;

	emit_event(BLOCK_REASON_RXRPC);
	return -EPERM;
}

/* Block splice-to-UDP (ESP path, kernel 6.5+) */
SEC("lsm/socket_sendmsg")
int BPF_PROG(block_udp_splice, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	struct sock *sk;

	if (ret)
		return ret;

	if (!(BPF_CORE_READ(msg, msg_flags) & MSG_SPLICE_PAGES))
		return 0;

	if (BPF_CORE_READ(sock, type) != SOCK_DGRAM)
		return 0;

	sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;

	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET &&
	    BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET6)
		return 0;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP)
		return 0;

	emit_event(BLOCK_REASON_UDP_SPLICE);
	return -EPERM;
}

/* Block UDP_ENCAP setsockopt (ESP path, pre-6.5 fallback) */
SEC("lsm/socket_setsockopt")
int BPF_PROG(block_udp_encap, struct socket *sock,
	     int level, int optname, int ret)
{
	if (ret)
		return ret;

	if (level != SOL_UDP || optname != UDP_ENCAP)
		return 0;

	emit_event(BLOCK_REASON_UDP_ENCAP);
	return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
