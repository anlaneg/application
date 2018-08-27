/*
 * log.h
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */

#ifndef LOG_H_
#define LOG_H_

#include <errno.h>
#include <string.h>

enum log_level {
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_INFO,
	LOG_LEVEL_LOG,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERROR,
};
extern enum log_level g_log_level;

void log_print(int fd, const char*fmt, ...);

#define LOG_INNER(level,fmt,...)\
do{\
		if(level >= g_log_level)\
		{\
			log_print(1,fmt,##__VA_ARGS__);\
		}\
}while(0)

#define LOG_COMMON(level,fmt,...)\
	LOG_INNER(level,"[%s:%d]: "fmt,__FILE__,__LINE__,##__VA_ARGS__);

#define LOG(fmt,...)\
	LOG_COMMON(LOG_LEVEL_LOG,fmt,##__VA_ARGS__)

#define ERROR(fmt,...)\
	LOG_COMMON(LOG_LEVEL_ERROR,fmt,##__VA_ARGS__)

#define DEBUG(fmt,...)\
	LOG_COMMON(LOG_LEVEL_DEBUG,fmt,##__VA_ARGS__)

#define WARN(fmt,...)\
	LOG_COMMON(LOG_LEVEL_WARN,fmt,##__VA_ARGS__)

#endif /* SRC_COMMON_LOG_H_ */
