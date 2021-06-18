// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

extern int bpf_kfunc_call_test2(struct sock *sk, __u32 a, __u32 b) __ksym;

SEC("classifier")
int kfunc_call_test2(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;
	__u64 a = 1ULL << 32;

	if (!sk)
		return -1;

	sk = bpf_sk_fullsock(sk);
	if (!sk)
		return -1;

	a = bpf_kfunc_call_test2((struct sock *)sk, 1, 2);

	char fmt[] = "MWC: bpf_kfunc_call_test2() => '%llx'\n";
	bpf_trace_printk(fmt, sizeof(fmt), a);

	return 0;
}

char _license[] SEC("license") = "GPL";
