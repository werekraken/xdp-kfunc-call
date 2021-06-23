#include <linux/init.h>
#include <linux/filter.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matthew Cover");

u64 noinline test1(struct sock *sk, u32 a, u64 b, u32 c, u64 d) {       
	return a + b + c + d;
}

int noinline test2(struct sock *sk, u32 a, u32 b) {
	return a + b;
}

struct sock * noinline test3(struct sock *sk) {
	return sk;
}

static struct a_kmod_hook a_hook = {
	.test1 = test1,
	.test2 = test2,
	.test3 = test3,
};

int __init a_kmod_init(void) {
	printk(KERN_ALERT "a_kmod: init\n");

	RCU_INIT_POINTER(a_kmod_hook, &a_hook);

	printk(KERN_ALERT "a_kmod: end init\n");

	return 0;
}

void __exit a_kmod_exit(void) {
	printk(KERN_ALERT "a_kmod: exit\n");

	RCU_INIT_POINTER(a_kmod_hook, NULL);

	printk(KERN_ALERT "a_kmod: end exit\n");
}

module_init(a_kmod_init);
module_exit(a_kmod_exit);
