#ifndef __LOGGING_H__
#define __LOGGING_H__

#define THOR_DEBUG 1

#define LOG_TAG "THOR: "

#if THOR_DEBUG
#   define LOG_DEBUG(format, args...) \
        printk(KERN_DEBUG LOG_TAG format "\n", ##args);
#else
#   define LOG_DEBUG(format, args...) do {} while(0);
#endif
#define LOG_ERROR(format, args...) \
    printk(KERN_ERR LOG_TAG format "\n", ##args);
#define LOG_INFO(format, args...) \
    printk(KERN_INFO LOG_TAG format "\n", ##args);

#endif /* __LOGGING_H__ */

