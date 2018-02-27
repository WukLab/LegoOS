/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TERMIOS_H_
#define _LEGO_TERMIOS_H_

typedef unsigned char	cc_t;
typedef unsigned int	speed_t;
typedef unsigned int	tcflag_t;

struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

#define NCC 8
struct termio {
	unsigned short c_iflag;		/* input mode flags */
	unsigned short c_oflag;		/* output mode flags */
	unsigned short c_cflag;		/* control mode flags */
	unsigned short c_lflag;		/* local mode flags */
	unsigned char  c_line;		/* line discipline */
	unsigned char  c_cc[NCC];	/* control characters */
};

#define NCCS 17
struct termios {
	tcflag_t c_iflag;		/* input mode flags */
	tcflag_t c_oflag;		/* output mode flags */
	tcflag_t c_cflag;		/* control mode flags */
	tcflag_t c_lflag;		/* local mode flags */
	cc_t c_line;			/* line discipline */
	cc_t c_cc[NCCS];		/* control characters */
	speed_t c_ispeed;		/* input speed */
	speed_t c_ospeed;		/* output speed */
};

/*
 *	intr=^C		quit=^\		erase=del	kill=^U
 *	eof=^D		vtime=\0	vmin=\1		sxtc=\0
 *	start=^Q	stop=^S		susp=^Z		eol=\0
 *	reprint=^R	discard=^U	werase=^W	lnext=^V
 *	eol2=\0
 */
#define INIT_C_CC "\003\034\177\025\004\0\1\0\021\023\032\0\022\017\027\026\0"

/*
 * c_cc characters
 */
#define VINTR		0
#define VQUIT		1
#define VERASE		2
#define VKILL		3
#define VEOF		4
#define VTIME		5
#define VMIN		6
#define VSWTC		7
#define VSTART		8
#define VSTOP		9
#define VSUSP		10
#define VEOL		11
#define VREPRINT	12
#define VDISCARD	13
#define VWERASE		14
#define VLNEXT		15
#define VEOL2		16

/*
 * c_iflag bits
 */
#define IGNBRK	0000001
#define BRKINT	0000002
#define IGNPAR	0000004
#define PARMRK	0000010
#define INPCK	0000020	/* Enable input parity checking						*/
#define ISTRIP	0000040	/* Strip off eighth bit							*/
#define INLCR	0000100	/* Translate NL to CR on input						*/
#define IGNCR	0000200	/* Ignore carriage return on input					*/
#define ICRNL	0000400	/* Translate carriage return to newline on input (unless IGNCR is set)	*/
#define IUCLC	0001000	/* Map uppercase characters to lowercase on input			*/
#define IXON	0002000	/* Enable XON/XOFF flow control on output				*/
#define IXANY	0004000	/* Typing any character will restart stopped output. (Default is START)	*/
#define IXOFF	0010000	/* Enable XON/XOFF flow control on input				*/
#define IMAXBEL	0020000	/* Ring bell when input queue is full					*/
#define IUTF8	0040000	/* Input is UTF8							*/

/*
 * c_oflag bits
 */
#define OPOST	0000001	/* Enable following output processing					*/
#define OLCUC	0000002	/* Map lowercase characters to uppercase on output			*/
#define ONLCR	0000004	/* Map NL to CR-NL on output						*/
#define OCRNL	0000010	/* Map CR to NL on output						*/
#define ONOCR	0000020	/* Do not output CR at columm 0						*/
#define ONLRET	0000040	/* NL performs CR function						*/
#define OFILL	0000100	/* Send fill characters for a delay, rather than using a timed delay	*/
#define OFDEL	0000200	/* Fill character is ASCII DEL (0177). If unset, it is ('\0')		*/
#define NLDLY	0000400	/* Newline delay mask							*/
#define   NL0	0000000
#define   NL1	0000400
#define CRDLY	0003000	/* Carriage return delay mask						*/
#define   CR0	0000000
#define   CR1	0001000
#define   CR2	0002000
#define   CR3	0003000
#define TABDLY	0014000	/* Horizontal tab delay mask						*/
#define   TAB0	0000000
#define   TAB1	0004000
#define   TAB2	0010000
#define   TAB3	0014000
#define   XTABS	0014000
#define BSDLY	0020000	/* Backspace delay mask							*/
#define   BS0	0000000
#define   BS1	0020000
#define VTDLY	0040000	/* Vertical tab delay mask						*/
#define   VT0	0000000
#define   VT1	0040000
#define FFDLY	0100000	/* Form feed delay mask							*/
#define   FF0	0000000
#define   FF1	0100000

/*
 * c_lflag bits
 */
#define ISIG	0000001	/* When any of INTR, QUIT, SUSP, DSUSP are received, genrate signals	*/
#define ICANON	0000002	/* Enable canonical mode						*/
#define XCASE	0000004	/* If ICANON is set, terminal is uppercase only				*/
#define ECHO	0000010 /* Echo input characters						*/
#define ECHOE	0000020	/* If ICANON is set, the ERASE char erases the preceding input char	*/
#define ECHOK	0000040 /* If ICANON is set, the KILL char erases the current line		*/
#define ECHONL	0000100	/* If ICANON is set, echo the NL char even if ECHO is not set		*/
#define NOFLSH	0000200	/* Disable flushing the input and output queues when generating signals	*/
#define TOSTOP	0000400	/* Send SIGTTOU to who tries to write to its controlling terminal	*/
#define ECHOCTL	0001000	/* If ECHO is set, special characters are echoed as ^X			*/
#define ECHOPRT	0002000	/* If ICANON and ECHO are set, chars are printed as being erased	*/
#define ECHOKE	0004000	/* If ICANON is set, KILL is echoed by erasing each char on the line	*/
#define FLUSHO	0010000	/* Output is being flushed						*/
#define PENDIN	0040000	/* All chars in input queue are reprinted when the next char is read	*/
#define IEXTEN	0100000	/* Enable implementation-defined input processing			*/
#define EXTPROC	0200000

/*
 * c_cflag bit meaning
 */
#define CBAUD	0010017
#define  B0	0000000	/* hang up */
#define  B50	0000001
#define  B75	0000002
#define  B110	0000003
#define  B134	0000004
#define  B150	0000005
#define  B200	0000006
#define  B300	0000007
#define  B600	0000010
#define  B1200	0000011
#define  B1800	0000012
#define  B2400	0000013
#define  B4800	0000014
#define  B9600	0000015
#define  B19200	0000016
#define  B38400	0000017
#define  EXTA	B19200
#define  EXTB	B38400
#define CSIZE	0000060
#define   CS5	0000000
#define   CS6	0000020
#define   CS7	0000040
#define   CS8	0000060
#define CSTOPB	0000100
#define CREAD	0000200
#define PARENB	0000400
#define PARODD	0001000
#define HUPCL	0002000
#define CLOCAL	0004000
#define CBAUDEX 0010000
#define    BOTHER 0010000
#define    B57600 0010001
#define   B115200 0010002
#define   B230400 0010003
#define   B460800 0010004
#define   B500000 0010005
#define   B576000 0010006
#define   B921600 0010007
#define  B1000000 0010010
#define  B1152000 0010011
#define  B1500000 0010012
#define  B2000000 0010013
#define  B2500000 0010014
#define  B3000000 0010015
#define  B3500000 0010016
#define  B4000000 0010017
#define CIBAUD	  002003600000	/* input baud rate */
#define CMSPAR	  010000000000	/* mark or space (stick) parity */
#define CRTSCTS	  020000000000	/* flow control */

#define IBSHIFT	  16		/* Shift from CBAUD to CIBAUD */

/*
 * modem lines
 */
#define TIOCM_LE	0x001
#define TIOCM_DTR	0x002
#define TIOCM_RTS	0x004
#define TIOCM_ST	0x008
#define TIOCM_SR	0x010
#define TIOCM_CTS	0x020
#define TIOCM_CAR	0x040
#define TIOCM_RNG	0x080
#define TIOCM_DSR	0x100
#define TIOCM_CD	TIOCM_CAR
#define TIOCM_RI	TIOCM_RNG
#define TIOCM_OUT1	0x2000
#define TIOCM_OUT2	0x4000
#define TIOCM_LOOP	0x8000

/*
 * tcflow() and TCXONC use these
 */
#define	TCOOFF		0
#define	TCOON		1
#define	TCIOFF		2
#define	TCION		3

/*
 * tcflush() and TCFLSH use these
 */
#define	TCIFLUSH	0
#define	TCOFLUSH	1
#define	TCIOFLUSH	2

/*
 * tcsetattr uses these
 */
#define	TCSANOW		0
#define	TCSADRAIN	1
#define	TCSAFLUSH	2

#define INTR_CHAR(tty)		((tty)->termios.c_cc[VINTR])
#define QUIT_CHAR(tty)		((tty)->termios.c_cc[VQUIT])
#define ERASE_CHAR(tty)		((tty)->termios.c_cc[VERASE])
#define KILL_CHAR(tty)		((tty)->termios.c_cc[VKILL])
#define EOF_CHAR(tty)		((tty)->termios.c_cc[VEOF])
#define TIME_CHAR(tty)		((tty)->termios.c_cc[VTIME])
#define MIN_CHAR(tty)		((tty)->termios.c_cc[VMIN])
#define SWTC_CHAR(tty)		((tty)->termios.c_cc[VSWTC])
#define START_CHAR(tty)		((tty)->termios.c_cc[VSTART])
#define STOP_CHAR(tty)		((tty)->termios.c_cc[VSTOP])
#define SUSP_CHAR(tty)		((tty)->termios.c_cc[VSUSP])
#define EOL_CHAR(tty)		((tty)->termios.c_cc[VEOL])
#define REPRINT_CHAR(tty)	((tty)->termios.c_cc[VREPRINT])
#define DISCARD_CHAR(tty)	((tty)->termios.c_cc[VDISCARD])
#define WERASE_CHAR(tty)	((tty)->termios.c_cc[VWERASE])
#define LNEXT_CHAR(tty)		((tty)->termios.c_cc[VLNEXT])
#define EOL2_CHAR(tty)		((tty)->termios.c_cc[VEOL2])

#define _I_FLAG(tty, f)		((tty)->termios.c_iflag & (f))
#define _O_FLAG(tty, f)		((tty)->termios.c_oflag & (f))
#define _C_FLAG(tty, f)		((tty)->termios.c_cflag & (f))
#define _L_FLAG(tty, f)		((tty)->termios.c_lflag & (f))

#define I_IGNBRK(tty)		_I_FLAG((tty), IGNBRK)
#define I_BRKINT(tty)		_I_FLAG((tty), BRKINT)
#define I_IGNPAR(tty)		_I_FLAG((tty), IGNPAR)
#define I_PARMRK(tty)		_I_FLAG((tty), PARMRK)
#define I_INPCK(tty)		_I_FLAG((tty), INPCK)
#define I_ISTRIP(tty)		_I_FLAG((tty), ISTRIP)
#define I_INLCR(tty)		_I_FLAG((tty), INLCR)
#define I_IGNCR(tty)		_I_FLAG((tty), IGNCR)
#define I_ICRNL(tty)		_I_FLAG((tty), ICRNL)
#define I_IUCLC(tty)		_I_FLAG((tty), IUCLC)
#define I_IXON(tty)		_I_FLAG((tty), IXON)
#define I_IXANY(tty)		_I_FLAG((tty), IXANY)
#define I_IXOFF(tty)		_I_FLAG((tty), IXOFF)
#define I_IMAXBEL(tty)		_I_FLAG((tty), IMAXBEL)
#define I_IUTF8(tty)		_I_FLAG((tty), IUTF8)

#define O_OPOST(tty)		_O_FLAG((tty), OPOST)
#define O_OLCUC(tty)		_O_FLAG((tty), OLCUC)
#define O_ONLCR(tty)		_O_FLAG((tty), ONLCR)
#define O_OCRNL(tty)		_O_FLAG((tty), OCRNL)
#define O_ONOCR(tty)		_O_FLAG((tty), ONOCR)
#define O_ONLRET(tty)		_O_FLAG((tty), ONLRET)
#define O_OFILL(tty)		_O_FLAG((tty), OFILL)
#define O_OFDEL(tty)		_O_FLAG((tty), OFDEL)
#define O_NLDLY(tty)		_O_FLAG((tty), NLDLY)
#define O_CRDLY(tty)		_O_FLAG((tty), CRDLY)
#define O_TABDLY(tty)		_O_FLAG((tty), TABDLY)
#define O_BSDLY(tty)		_O_FLAG((tty), BSDLY)
#define O_VTDLY(tty)		_O_FLAG((tty), VTDLY)
#define O_FFDLY(tty)		_O_FLAG((tty), FFDLY)

#define C_BAUD(tty)		_C_FLAG((tty), CBAUD)
#define C_CSIZE(tty)		_C_FLAG((tty), CSIZE)
#define C_CSTOPB(tty)		_C_FLAG((tty), CSTOPB)
#define C_CREAD(tty)		_C_FLAG((tty), CREAD)
#define C_PARENB(tty)		_C_FLAG((tty), PARENB)
#define C_PARODD(tty)		_C_FLAG((tty), PARODD)
#define C_HUPCL(tty)		_C_FLAG((tty), HUPCL)
#define C_CLOCAL(tty)		_C_FLAG((tty), CLOCAL)
#define C_CIBAUD(tty)		_C_FLAG((tty), CIBAUD)
#define C_CRTSCTS(tty)		_C_FLAG((tty), CRTSCTS)
#define C_CMSPAR(tty)		_C_FLAG((tty), CMSPAR)

#define L_ISIG(tty)		_L_FLAG((tty), ISIG)
#define L_ICANON(tty)		_L_FLAG((tty), ICANON)
#define L_XCASE(tty)		_L_FLAG((tty), XCASE)
#define L_ECHO(tty)		_L_FLAG((tty), ECHO)
#define L_ECHOE(tty)		_L_FLAG((tty), ECHOE)
#define L_ECHOK(tty)		_L_FLAG((tty), ECHOK)
#define L_ECHONL(tty)		_L_FLAG((tty), ECHONL)
#define L_NOFLSH(tty)		_L_FLAG((tty), NOFLSH)
#define L_TOSTOP(tty)		_L_FLAG((tty), TOSTOP)
#define L_ECHOCTL(tty)		_L_FLAG((tty), ECHOCTL)
#define L_ECHOPRT(tty)		_L_FLAG((tty), ECHOPRT)
#define L_ECHOKE(tty)		_L_FLAG((tty), ECHOKE)
#define L_FLUSHO(tty)		_L_FLAG((tty), FLUSHO)
#define L_PENDIN(tty)		_L_FLAG((tty), PENDIN)
#define L_IEXTEN(tty)		_L_FLAG((tty), IEXTEN)
#define L_EXTPROC(tty)		_L_FLAG((tty), EXTPROC)

#endif /* _LEGO_TERMIOS_H_ */
