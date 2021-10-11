#ifndef LOG_H
#define LOG_H

/*
 * Description:
 *	log message to console
 * Input:
 *	func:Current function name
 *	msg:Message to write
 *	...:other args
 */
void bmLog(const char* func, const char* msg, ...);

#endif
