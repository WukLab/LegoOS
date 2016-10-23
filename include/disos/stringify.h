#ifndef _DISOS_STRINGIFY_H_
#define _DISOS_STRINGIFY_H_

/*
 * Indirect stringification. Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 */

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#endif /* _DISOS_STRINGIFY_H_ */
