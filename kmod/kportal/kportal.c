#include <linux/module.h>

static int kportal_init(void) {
	 printk(KERN_INFO "kportal init ok!\n");
	return 0;
}

static void kportal_exit(void) {
	
}
module_init(kportal_init);
module_exit(kportal_exit);
