#ifndef _LEGO_TRACEPOINT_H_
#define _LEGO_TRACEPOINT_H_

struct trace_print_flags {
	unsigned long		mask;
	const char		*name;
};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct tracepoint {
	const char *name;		/* Tracepoint name */
	void (*regfunc)(void);
	void (*unregfunc)(void);
	struct tracepoint_func *funcs;
};

#endif /* _LEGO_TRACEPOINT_H_ */
