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

static __u64 boot_time_ns;

static int handle_event(void *ctx, void *data, size_t len)
{
	if (len < sizeof(struct block_event))
		return 0;

	struct block_event *evt = data;
	time_t event_sec = (evt->ts + boot_time_ns) / 1000000000ULL;
	struct tm *tm = localtime(&event_sec);
	char ts[32];
	const char *what;

	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
	switch (evt->reason) {
	case BLOCK_REASON_RXRPC:      what = "AF_RXRPC socket";       break;
	case BLOCK_REASON_XFRM:       what = "XFRM from container";   break;
	case BLOCK_REASON_UDP_SPLICE: what = "UDP MSG_SPLICE_PAGES";  break;
	default:                      what = "unknown";               break;
	}
	fprintf(stderr, "block-dirtyfrag: BLOCKED %s pid=%-8u comm=%.*s time=%s\n",
		what, evt->pid, 16, evt->comm, ts);
	return 0;
}

int main(int argc, char **argv)
{
	struct block_dirtyfrag_bpf *skel;
	struct ring_buffer *rb;

	skel = block_dirtyfrag_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "block-dirtyfrag: failed to load BPF program\n");
		return 1;
	}

	if (block_dirtyfrag_bpf__attach(skel)) {
		fprintf(stderr, "block-dirtyfrag: failed to attach BPF program\n");
		block_dirtyfrag_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr, "block-dirtyfrag: blocker active — AF_RXRPC + XFRM-from-container + UDP-splice blocked\n");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "block-dirtyfrag: failed to create ring buffer\n");
		block_dirtyfrag_bpf__destroy(skel);
		return 1;
	}

	struct timespec rt, bt;
	clock_gettime(CLOCK_REALTIME, &rt);
	clock_gettime(CLOCK_BOOTTIME, &bt);
	boot_time_ns = (__u64)rt.tv_sec * 1000000000ULL + rt.tv_nsec
		     - (__u64)bt.tv_sec * 1000000000ULL - bt.tv_nsec;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		ring_buffer__poll(rb, 250);

	fprintf(stderr, "block-dirtyfrag: detaching blocker\n");
	ring_buffer__free(rb);
	block_dirtyfrag_bpf__destroy(skel);
	return 0;
}
