// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 StackPath, LLC */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_tcp_helpers.h"

#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <sys/socket.h>
#include <linux/tcp.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

/* The manipulable part of the tuple. */
struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	/* Layer 3 protocol */
	u_int16_t l3num;
};

/* This contains the information to distinguish a connection. */
struct nf_conntrack_tuple {
	struct nf_conntrack_man src;

	/* These are the parts of the tuple which are fixed. */
	struct {
		union nf_inet_addr u3;
		union {
			/* Add other protocols here. */
			__be16 all;

			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type, code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;

		/* The protocol. */
		u_int8_t protonum;

		/* The direction (for tuplehash) */
		u_int8_t dir;
	} dst;
};

#define bpf_printk(fmt, ...)                                       \
({                                                                 \
	char ____fmt[] = fmt;                                      \
	bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

extern void xdp_printk_nfct_tuple(struct nf_conntrack_tuple *tuple) __ksym;

SEC("xdp")
int kfunc_call_xdp_printk_nfct_tuple(struct xdp_md *ctx)
{

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *cursor = data;
	int hdrsize = 0;
	__u64 a = 1ULL << 32;

	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;

	struct nf_conntrack_tuple tuple;

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

	memset(&tuple, 0, sizeof(tuple));

	tuple.dst.protonum = IPPROTO_TCP;
	tuple.src.l3num = AF_INET;

	tuple.src.u3.ip = iph->saddr;
	tuple.dst.u3.ip = iph->daddr;

	tuple.src.u.tcp.port = tcph->source;
	tuple.dst.u.tcp.port = tcph->dest;

	xdp_printk_nfct_tuple(&tuple);

	char fmt[] = "MWC: xdp ran xdp_printf_nfct_tuple()'\n";
	bpf_trace_printk(fmt, sizeof(fmt));

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
