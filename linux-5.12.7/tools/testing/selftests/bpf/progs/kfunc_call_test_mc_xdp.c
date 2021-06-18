// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 StackPath, LLC */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_tcp_helpers.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <sys/socket.h>
#include <linux/tcp.h>

#define bpf_printk(fmt, ...)                                       \
({                                                                 \
	char ____fmt[] = fmt;                                      \
	bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

#define NULL 0

extern int bpf_kfunc_call_test2(struct sock *sk, __u32 a, __u32 b) __ksym;

SEC("xdp")
int kfunc_call_test2(struct xdp_md *ctx)
{

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *cursor = data;
	int hdrsize = 0;
	__u64 a = 1ULL << 32;

	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;

	struct bpf_sock *sk = NULL;
	struct bpf_sock_tuple tuple;

	int err = 0;

	eth = cursor;
	hdrsize = sizeof(*eth);

	if (cursor + hdrsize > data_end)
		return XDP_PASS;
	cursor += hdrsize;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = cursor;
	hdrsize = sizeof(*iph);

	if (cursor + hdrsize > data_end)
		return XDP_PASS;
	cursor += hdrsize;

	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	tcph = cursor;
	hdrsize = sizeof(*tcph);

	if (cursor + hdrsize > data_end)
		return XDP_PASS;
	cursor += hdrsize;

	tuple.ipv4.saddr = iph->saddr;
	tuple.ipv4.daddr = iph->daddr;
	tuple.ipv4.sport = tcph->source;
	tuple.ipv4.dport = tcph->dest;

	sk = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);


	if (!sk)
		return -1;

	a = bpf_kfunc_call_test2((struct sock *)sk, 1, 2);

	char fmt[] = "MWC: xdp bpf_kfunc_call_test2() => '%llx'\n";
	bpf_trace_printk(fmt, sizeof(fmt), a);

	if (sk)
		bpf_sk_release(sk);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
