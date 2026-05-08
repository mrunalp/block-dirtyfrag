#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "block_dirtyfrag.h"
#include "block_dirtyfrag.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

static int has_splice_to_socket(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f)
		return 0;
	char line[256];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, " splice_to_socket\n")) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	struct block_event *evt = data;
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char ts[32];
	const char *what;

	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
	switch (evt->reason) {
	case BLOCK_REASON_RXRPC:      what = "AF_RXRPC socket";   break;
	case BLOCK_REASON_UDP_SPLICE: what = "UDP splice (ESP)";  break;
	case BLOCK_REASON_UDP_ENCAP:  what = "UDP_ENCAP (ESP)";   break;
	default:                      what = "unknown";           break;
	}
	fprintf(stderr, "block-dirtyfrag: BLOCKED %s pid=%-8u comm=%.*s time=%s\n",
		what, evt->pid, 16, evt->comm, ts);
	return 0;
}

int main(int argc, char **argv)
{
	struct block_dirtyfrag_bpf *skel;
	struct ring_buffer *rb;
	int use_udp_encap;

	skel = block_dirtyfrag_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "block-dirtyfrag: failed to load BPF program\n");
		return 1;
	}

	use_udp_encap = !has_splice_to_socket();

	if (use_udp_encap)
		fprintf(stderr, "block-dirtyfrag: splice_to_socket not found — using UDP_ENCAP fallback\n");
	else
		fprintf(stderr, "block-dirtyfrag: splice_to_socket found — UDP splice hook is sufficient\n");

	skel->links.block_rxrpc = bpf_program__attach(skel->progs.block_rxrpc);
	if (!skel->links.block_rxrpc) {
		fprintf(stderr, "block-dirtyfrag: failed to attach block_rxrpc\n");
		block_dirtyfrag_bpf__destroy(skel);
		return 1;
	}

	skel->links.block_udp_splice = bpf_program__attach(skel->progs.block_udp_splice);
	if (!skel->links.block_udp_splice) {
		fprintf(stderr, "block-dirtyfrag: failed to attach block_udp_splice\n");
		block_dirtyfrag_bpf__destroy(skel);
		return 1;
	}

	if (use_udp_encap) {
		skel->links.block_udp_encap = bpf_program__attach(skel->progs.block_udp_encap);
		if (!skel->links.block_udp_encap) {
			fprintf(stderr, "block-dirtyfrag: failed to attach block_udp_encap\n");
			block_dirtyfrag_bpf__destroy(skel);
			return 1;
		}
	}

	fprintf(stderr, "block-dirtyfrag: blocker active — AF_RXRPC + UDP splice%s blocked\n",
		use_udp_encap ? " + UDP_ENCAP" : "");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "block-dirtyfrag: failed to create ring buffer\n");
		block_dirtyfrag_bpf__destroy(skel);
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		ring_buffer__poll(rb, 250);

	fprintf(stderr, "block-dirtyfrag: detaching blocker\n");
	ring_buffer__free(rb);
	block_dirtyfrag_bpf__destroy(skel);
	return 0;
}
