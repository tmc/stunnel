/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2001 Michal Trojnara <Michal.Trojnara@mirt.net>
 *                 All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

typedef struct {
    int local_rd, local_wr; /* Read and write side of local file descriptor */
    int negotiation_level; /* fdscanf() or fdprintf() number in negotiate() */
} CLI;

typedef enum {
    STATE_NONE,         /* Not used */
    STATE_ACCEPT,       /* On accept() */
    STATE_CONNECT,      /* On connect() */
    STATE_NEGOTIATE,    /* On negotiate() */
    STATE_SSL_ACCEPT,   /* On SSL_accept() */
    STATE_SSL_CONNECT,  /* On SSL_connect() */
    STATE_SSL_SHUTDOWN, /* On SSL_shutdown() */
    STATE_SSL,          /* On SSL_read or SSL_write */
    STATE_PLAIN,        /* On readsocket() or writesocket() */
    STATE_USER          /* On auth_user */
} STATE;

typedef struct {
    STATE state;
    int rd; /* Waiting for read */
    int wr; /* Waiting for write */
    CLI *cli; /* Client structure if state>STATE_ACCEPT */
} FD;

#endif /* defined CLIENT_H */

/* End of client.h */
