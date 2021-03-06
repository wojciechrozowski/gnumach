/*
 *	Declarations of AX.25 type objects.
 *
 *	Alan Cox (GW4PTS) 	10/11/93
 */
 
#ifndef _AX25_H
#define _AX25_H 
#include <linux/ax25.h>

#define AX25_SLOWHZ			10	/* Run timing at 1/10 second - gives us better resolution for 56kbit links */

#define	AX25_T1CLAMPLO  		(1 * AX25_SLOWHZ)	/* If defined, clamp at 1 second **/
#define	AX25_T1CLAMPHI 			(30 * AX25_SLOWHZ)	/* If defined, clamp at 30 seconds **/

#define	AX25_BPQ_HEADER_LEN		16
#define	AX25_KISS_HEADER_LEN		1

#define	AX25_HEADER_LEN			17
#define	AX25_ADDR_LEN			7
#define	AX25_DIGI_HEADER_LEN		(AX25_MAX_DIGIS * AX25_ADDR_LEN)
#define	AX25_MAX_HEADER_LEN		(AX25_HEADER_LEN + AX25_DIGI_HEADER_LEN)

/* AX.25 Protocol IDs */
#define AX25_P_ROSE			0x01
#define AX25_P_IP			0xCC
#define AX25_P_ARP			0xCD
#define AX25_P_TEXT 			0xF0
#define AX25_P_NETROM 			0xCF
#define	AX25_P_SEGMENT			0x08

/* AX.25 Segment control values */
#define	AX25_SEG_REM			0x7F
#define	AX25_SEG_FIRST			0x80

#define AX25_CBIT			0x80	/* Command/Response bit */
#define AX25_EBIT			0x01	/* HDLC Address Extension bit */
#define AX25_HBIT			0x80	/* Has been repeated bit */

#define AX25_SSSID_SPARE		0x60	/* Unused bits in SSID for standard AX.25 */
#define AX25_ESSID_SPARE		0x20	/* Unused bits in SSID for extended AX.25 */
#define AX25_DAMA_FLAG			0x20	/* Well, it is *NOT* unused! (dl1bke 951121 */

#define	AX25_COND_ACK_PENDING		0x01
#define	AX25_COND_REJECT		0x02
#define	AX25_COND_PEER_RX_BUSY		0x04
#define	AX25_COND_OWN_RX_BUSY		0x08

#ifndef _LINUX_NETDEVICE_H
#include <linux/netdevice.h>
#endif

/*
 * These headers are taken from the KA9Q package by Phil Karn. These specific
 * files have been placed under the GPL (not the whole package) by Phil.
 *
 *
 * Copyright 1991 Phil Karn, KA9Q
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 dated June, 1991.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program;  if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave., Cambridge, MA 02139, USA.
 */

/* Upper sub-layer (LAPB) definitions */

/* Control field templates */
#define	AX25_I			0x00	/* Information frames */
#define	AX25_S			0x01	/* Supervisory frames */
#define	AX25_RR			0x01	/* Receiver ready */
#define	AX25_RNR		0x05	/* Receiver not ready */
#define	AX25_REJ		0x09	/* Reject */
#define	AX25_U			0x03	/* Unnumbered frames */
#define	AX25_SABM		0x2f	/* Set Asynchronous Balanced Mode */
#define	AX25_SABME		0x6f	/* Set Asynchronous Balanced Mode Extended */
#define	AX25_DISC		0x43	/* Disconnect */
#define	AX25_DM			0x0f	/* Disconnected mode */
#define	AX25_UA			0x63	/* Unnumbered acknowledge */
#define	AX25_FRMR		0x87	/* Frame reject */
#define	AX25_UI			0x03	/* Unnumbered information */

#define	AX25_PF			0x10	/* Poll/final bit for standard AX.25 */
#define	AX25_EPF		0x01	/* Poll/final bit for extended AX.25 */

#define AX25_ILLEGAL		0x100	/* Impossible to be a real frame type */

#define	AX25_POLLOFF		0
#define	AX25_POLLON		1

/* AX25 L2 C-bit */
#define AX25_COMMAND		1
#define AX25_RESPONSE		2

/* Define Link State constants. */

enum { 
	AX25_STATE_0,
	AX25_STATE_1,
	AX25_STATE_2,
	AX25_STATE_3,
	AX25_STATE_4
};

#define	AX25_MAX_DEVICES	20	/* Max No of AX.25 devices */

#define AX25_MODULUS 		8	/*  Standard AX.25 modulus */
#define	AX25_EMODULUS		128	/*  Extended AX.25 modulus */

enum {
	AX25_VALUES_IPDEFMODE,	/* 0=DG 1=VC */
	AX25_VALUES_AXDEFMODE,	/* 0=Normal 1=Extended Seq Nos */
	AX25_VALUES_BACKOFF,	/* 0=None 1=Linear 2=Exponential */
	AX25_VALUES_CONMODE,	/* Allow connected modes - 0=No 1=no "PID text" 2=all PIDs */
	AX25_VALUES_WINDOW,	/* Default window size for standard AX.25 */
	AX25_VALUES_EWINDOW,	/* Default window size for extended AX.25 */
	AX25_VALUES_T1,		/* Default T1 timeout value */
	AX25_VALUES_T2,		/* Default T2 timeout value */
	AX25_VALUES_T3,		/* Default T3 timeout value */
	AX25_VALUES_IDLE,	/* Connected mode idle timer */
	AX25_VALUES_N2,		/* Default N2 value */
	AX25_VALUES_PACLEN,	/* AX.25 MTU */
	AX25_MAX_VALUES		/* THIS MUST REMAIN THE LAST ENTRY OF THIS LIST */
};

#define	AX25_DEF_IPDEFMODE	0			/* Datagram */
#define	AX25_DEF_AXDEFMODE	0			/* Normal */
#define	AX25_DEF_BACKOFF	1			/* Linear backoff */
#define	AX25_DEF_CONMODE	2			/* Connected mode allowed */
#define	AX25_DEF_WINDOW		2			/* Window=2 */
#define	AX25_DEF_EWINDOW	32			/* Module-128 Window=32 */
#define	AX25_DEF_T1		(10 * AX25_SLOWHZ)	/* T1=10s */
#define	AX25_DEF_T2		(3 * AX25_SLOWHZ)	/* T2=3s  */
#define	AX25_DEF_T3		(300 * AX25_SLOWHZ)	/* T3=300s */
#define	AX25_DEF_N2		10			/* N2=10 */
#define AX25_DEF_IDLE		(0 * 60 * AX25_SLOWHZ)	/* Idle=None */
#define AX25_DEF_PACLEN		256			/* Paclen=256 */

typedef struct ax25_uid_assoc {
	struct ax25_uid_assoc	*next;
	uid_t			uid;
	ax25_address		call;
} ax25_uid_assoc;

typedef struct {
	ax25_address		calls[AX25_MAX_DIGIS];
	unsigned char		repeated[AX25_MAX_DIGIS];
	unsigned char		ndigi;
	char			lastrepeat;
} ax25_digi;

typedef struct ax25_cb {
	struct ax25_cb		*next;
	ax25_address		source_addr, dest_addr;
	struct device		*device;
	unsigned char		dama_slave, iamdigi;
	unsigned char		state, modulus, pidincl;
	unsigned short		vs, vr, va;
	unsigned char		condition, backoff;
	unsigned char		n2, n2count;
	unsigned short		t1, t2, t3, idle, rtt;
	unsigned short		t1timer, t2timer, t3timer, idletimer;
	unsigned short		paclen;
	unsigned short		fragno, fraglen;
	ax25_digi		*digipeat;
	struct sk_buff_head	write_queue;
	struct sk_buff_head	reseq_queue;
	struct sk_buff_head	ack_queue;
	struct sk_buff_head	frag_queue;
	unsigned char		window;
	struct timer_list	timer;
	struct sock		*sk;		/* Backlink to socket */
} ax25_cb;

#ifndef _LINUX_SYSCTL_H
#include <linux/sysctl.h>
#endif

struct ax25_dev {
	char			name[20];
	struct device		*dev;
	struct device		*forward;
	struct ctl_table	systable[AX25_MAX_VALUES+1];
	int			values[AX25_MAX_VALUES];
};

/* af_ax25.c */
extern ax25_address null_ax25_address;
extern char *ax2asc(ax25_address *);
extern ax25_address *asc2ax(char *);
extern int  ax25cmp(ax25_address *, ax25_address *);
extern ax25_cb *ax25_send_frame(struct sk_buff *, int, ax25_address *, ax25_address *, ax25_digi *, struct device *);
extern ax25_cb *ax25_find_cb(ax25_address *, ax25_address *, ax25_digi *, struct device *);
extern void ax25_destroy_socket(ax25_cb *);
extern struct device *ax25rtr_get_dev(ax25_address *);
extern int  ax25_encapsulate(struct sk_buff *, struct device *, unsigned short,
	void *, void *, unsigned int);
extern int  ax25_rebuild_header(void *, struct device *, unsigned long, struct sk_buff *);
extern ax25_uid_assoc *ax25_uid_list;
extern int  ax25_uid_policy;
extern ax25_address *ax25_findbyuid(uid_t);
extern void ax25_queue_xmit(struct sk_buff *, struct device *, int);
extern int  ax25_dev_is_dama_slave(struct device *);	/* dl1bke 951121 */

#include <net/ax25call.h>

/* ax25_in.c */
extern int  ax25_process_rx_frame(ax25_cb *, struct sk_buff *, int, int);

/* ax25_out.c */
extern void ax25_output(ax25_cb *, int, struct sk_buff *);
extern void ax25_kick(ax25_cb *);
extern void ax25_transmit_buffer(ax25_cb *, struct sk_buff *, int);
extern void ax25_nr_error_recovery(ax25_cb *);
extern void ax25_establish_data_link(ax25_cb *);
extern void ax25_transmit_enquiry(ax25_cb *);
extern void ax25_enquiry_response(ax25_cb *);
extern void ax25_timeout_response(ax25_cb *);
extern void ax25_check_iframes_acked(ax25_cb *, unsigned short);
extern void dama_enquiry_response(ax25_cb *);			/* dl1bke 960114 */
extern void dama_establish_data_link(ax25_cb *);

/* ax25_route.c */
extern struct ax25_dev ax25_device[];
extern int  ax25_rt_get_info(char *, char **, off_t, int, int);
extern int  ax25_cs_get_info(char *, char **, off_t, int, int);
extern int  ax25_rt_autobind(ax25_cb *, ax25_address *);
extern ax25_digi *ax25_rt_find_path(ax25_address *, struct device *);
extern void ax25_rt_build_path(struct sk_buff *, ax25_address *, ax25_address *, ax25_digi *);
extern void ax25_rt_device_down(struct device *);
extern int  ax25_rt_ioctl(unsigned int, void *);
extern char ax25_rt_mode_get(ax25_address *, struct device *);
extern int  ax25_dev_get_value(struct device *, int);
extern void ax25_dev_device_up(struct device *);
extern void ax25_dev_device_down(struct device *);
extern int  ax25_fwd_ioctl(unsigned int, struct ax25_fwd_struct *);
extern struct device *ax25_fwd_dev(struct device *);
extern void ax25_rt_free(void);

/* ax25_subr.c */
extern void ax25_clear_queues(ax25_cb *);
extern void ax25_frames_acked(ax25_cb *, unsigned short);
extern void ax25_requeue_frames(ax25_cb *);
extern int  ax25_validate_nr(ax25_cb *, unsigned short);
extern int  ax25_decode(ax25_cb *, struct sk_buff *, int *, int *, int *);
extern void ax25_send_control(ax25_cb *, int, int, int);
extern unsigned short ax25_calculate_t1(ax25_cb *);
extern void ax25_calculate_rtt(ax25_cb *);
extern unsigned char *ax25_parse_addr(unsigned char *, int, ax25_address *,
	ax25_address *, ax25_digi *, int *, int *);	/* dl1bke 951121 */
extern int  build_ax25_addr(unsigned char *, ax25_address *, ax25_address *,
	ax25_digi *, int, int);
extern int  size_ax25_addr(ax25_digi *);
extern void ax25_digi_invert(ax25_digi *, ax25_digi *);
extern void ax25_return_dm(struct device *, ax25_address *, ax25_address *, ax25_digi *);
extern void ax25_dama_on(ax25_cb *);	/* dl1bke 951121 */
extern void ax25_dama_off(ax25_cb *);	/* dl1bke 951121 */
extern void ax25_disconnect(ax25_cb *, int);

/* ax25_timer.c */
extern void ax25_set_timer(ax25_cb *);
extern void ax25_t1_timeout(ax25_cb *);
extern void ax25_link_failed(ax25_cb *, int);
extern int  (*ax25_protocol_function(unsigned int))(struct sk_buff *, ax25_cb *);
extern int  ax25_listen_mine(ax25_address *, struct device *);

/* sysctl_net_ax25.c */
extern void ax25_register_sysctl(void);
extern void ax25_unregister_sysctl(void);

/* ... */

extern ax25_cb *volatile ax25_list;

/* support routines for modules that use AX.25, in ax25_timer.c */
extern int  ax25_protocol_register(unsigned int, int (*)(struct sk_buff *, ax25_cb *));
extern void ax25_protocol_release(unsigned int);
extern int  ax25_linkfail_register(void (*)(ax25_cb *, int));
extern void ax25_linkfail_release(void (*)(ax25_cb *, int));
extern int  ax25_listen_register(ax25_address *, struct device *);
extern void ax25_listen_release(ax25_address *, struct device *);
extern int  ax25_protocol_is_registered(unsigned int);

#endif
