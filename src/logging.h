#ifndef LOGGING_H
#define LOGGING_H

#include "config.h"

#if THOR_DEBUG
#   define LOG_ERROR(format, args...) \
        printk(KERN_ERR LOG_TAG format "\n", ##args);
#   define LOG_INFO(format, args...) \
        printk(KERN_INFO LOG_TAG format "\n", ##args);
#   define LOG_WARN(format, args...) \
        printk(KERN_WARNING LOG_TAG format "\n", ##args);
#else
#   define LOG_ERROR(format, args...) do {} while(0);
#   define LOG_INFO(format, args...) do {} while(0);
#   define LOG_WARN(format, args...) do {} while(0);
#endif

#endif
