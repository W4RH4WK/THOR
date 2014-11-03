#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init thor_init(void)
{
    printk(KERN_INFO "thor_init()\n");
    return 0;
}

static void __exit thor_cleanup(void)
{
    printk(KERN_INFO "thor_cleanup()\n");
}

module_init(thor_init);
module_exit(thor_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Hirsch (W4RH4WK) <alexander.hirsch@student.uibk.ac.at>");
MODULE_AUTHOR("Franz-Josef Anton Friedrich Haider (krnylng) <Franz-Josef.Haider@student.uibk.ac.at>");
MODULE_DESCRIPTION("THOR - The Horrific Omnipotent Rootkit");

