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

/* I/O buffer size */
#define BUFFSIZE 16384

/* Undefine if you have problems with make_sockets() */
#define INET_SOCKET_PAIR

#include "common.h"
#include "proto.h"
#include "client.h"

#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

#ifdef HAVE_OPENSSL
#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#else
#include <lhash.h>
#include <ssl.h>
#include <err.h>
#endif

/* TCP wrapper */
#ifdef USE_LIBWRAP
#include <tcpd.h>
int allow_severity=LOG_NOTICE;
int deny_severity=LOG_WARNING;
#endif

#if SSLEAY_VERSION_NUMBER >= 0x0922
static unsigned char *sid_ctx=(unsigned char *)"stunnel SID";
    /* const allowed here */
#endif

extern SSL_CTX *ctx; /* global SSL context defined in ssl.c */
extern server_options options;

    /* SSL functions */
static void do_client(CLI *);
static int transfer(int, int, SSL *, int, int);
static void print_cipher(SSL *);
static int auth_user(struct sockaddr_in *);
static int connect_local(u32);
#ifndef USE_WIN32
static int make_sockets(int [2]);
#endif
static int connect_remote(u32);
static int waitforsocket(int, int);

void *client(void *local) {
    CLI *c;

    c=malloc(sizeof(CLI));
    if(!c) {
        log(LOG_ERR, "malloc failed");
        closesocket((int)local);
        return NULL;
    }
    if((int)local==STDIO_FILENO) { /* Read from STDIN, write to STDOUT */
        c->local_rd=0;
        c->local_wr=1;
    } else
        c->local_rd=c->local_wr=(int)local;
    do_client(c);
    free(c);
    return NULL;
}

static void do_client(CLI *c) {
    struct sockaddr_in addr;
    int addrlen;
    SSL *ssl;
    int remote;
    struct linger l;
    u32 ip;
#ifdef USE_LIBWRAP
    struct request_info request;
    int result;
#endif

    log(LOG_DEBUG, "%s started", options.servname);
    l.l_onoff=1;
    l.l_linger=0;
    addrlen=sizeof(addr);

    if(getpeername(c->local_rd, (struct sockaddr *)&addr, &addrlen)<0) {
        if(options.option&OPT_TRANSPARENT || get_last_socket_error()!=ENOTSOCK) {
            sockerror("getpeerbyname");
            goto cleanup_local;
        }
        /* Ignore ENOTSOCK error so 'local' doesn't have to be a socket */
    } else {
        /* It's a socket - lets setup options */
        if(set_socket_options(c->local_rd, 1)<0)
            goto cleanup_local;

#ifdef USE_LIBWRAP
        enter_critical_section(CRIT_LIBWRAP); /* libwrap is not mt-safe */
        request_init(&request, RQ_DAEMON, options.servname, RQ_FILE, c->local_rd, 0);
        fromhost(&request);
        result=hosts_access(&request);
        leave_critical_section(CRIT_LIBWRAP);
        if (!result) {
            enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
            log(LOG_WARNING, "Connection from %s:%d REFUSED by libwrap",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            leave_critical_section(CRIT_NTOA);
            log(LOG_DEBUG, "See hosts_access(5) for details");
            goto cleanup_local;
        }
#endif
        if(auth_user(&addr)<0) {
            enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
            log(LOG_WARNING, "Connection from %s:%d REFUSED by IDENT",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            leave_critical_section(CRIT_NTOA);
            goto cleanup_local;
        }
        enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
        log(LOG_NOTICE, "%s connected from %s:%d", options.servname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        leave_critical_section(CRIT_NTOA);
    }

    /* create connection to host/service */
    if(options.local_ip)
        ip=*options.local_ip;
    else if(options.option&OPT_TRANSPARENT)
        ip=addr.sin_addr.s_addr;
    else
        ip=0;
    if(options.option&OPT_REMOTE) { /* remote host */
        if((remote=connect_remote(ip))<0)
            goto cleanup_local; /* Failed to connect remote server */
        log(LOG_DEBUG, "Remote host connected");
        if(set_socket_options(remote, 2)<0)
            goto cleanup_remote;
    } else { /* local service */
        if((remote=connect_local(ip))<0)
            goto cleanup_local; /* Failed to spawn local service */
        log(LOG_DEBUG, "Local service connected");
    }

    /* negotiate protocol */
    if(negotiate(options.protocol, options.option&OPT_CLIENT,
            c->local_rd, c->local_wr, remote) <0) {
        log(LOG_ERR, "Protocol negotiations failed");
        goto cleanup_remote;
    }

    /* do the job */
    if(!(ssl=SSL_new(ctx))) {
        sslerror("SSL_new");
        goto cleanup_remote;
    }
#if SSLEAY_VERSION_NUMBER >= 0x0922
    SSL_set_session_id_context(ssl, sid_ctx, strlen(sid_ctx));
#endif
    if(options.option&OPT_CLIENT) {
        /* Attempt to use the most recent id in the session cache */
        if(ctx->session_cache_head)
            if(!SSL_set_session(ssl, ctx->session_cache_head))
                log(LOG_WARNING, "Cannot set SSL session id to most recent used");
        SSL_set_fd(ssl, remote);
        SSL_set_connect_state(ssl);
        if(SSL_connect(ssl)<=0) {
            sslerror("SSL_connect");
            goto cleanup_ssl;
        }
        print_cipher(ssl);
        if(transfer(c->local_rd, c->local_wr, ssl, remote, remote)<0)
            goto cleanup_ssl;
    } else {
        if(c->local_rd==c->local_wr)
            SSL_set_fd(ssl, c->local_rd);
        else {
           /* Does it make sence to have SSL on STDIN/STDOUT? */
            SSL_set_rfd(ssl, c->local_rd);
            SSL_set_wfd(ssl, c->local_wr);
        }
        SSL_set_accept_state(ssl);
        if(SSL_accept(ssl)<=0) {
            sslerror("SSL_accept");
            goto cleanup_ssl;
        }
        print_cipher(ssl);
        if(transfer(remote, remote, ssl, c->local_rd, c->local_wr)<0)
            goto cleanup_ssl;
    }
    /* No error - normal shutdown */
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    ERR_remove_state(0);
    closesocket(remote);
    if(c->local_rd==c->local_wr) /* Not stdio */
        closesocket(c->local_rd);
    goto done;
cleanup_ssl: /* close SSL and reset sockets */
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    ERR_remove_state(0);
cleanup_remote: /* reset remote and local socket */
    if(options.option&OPT_REMOTE)
        if(setsockopt(remote, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (remote)");
    closesocket(remote);
cleanup_local: /* reset local socket */
    if(c->local_rd==c->local_wr) {
        if(setsockopt(c->local_rd, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (local)");
        closesocket(c->local_rd);
    } else {
        if(setsockopt(c->local_rd, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (local_rd)");
        if(setsockopt(c->local_wr, SOL_SOCKET, SO_LINGER,
                (void *)&l, sizeof(l)) &&
                get_last_socket_error()!=ENOTSOCK)
            sockerror("linger (local_wr)");
    }
done:
#ifndef USE_FORK
    enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
    log(LOG_DEBUG, "%s finished (%d left)", options.servname,
        --options.clients);
    leave_critical_section(CRIT_CLIENTS);
#endif
    ; /* ANSI C compiler needs it */
}

static int transfer(int sock_rfd, int sock_wfd,
    SSL *ssl, int ssl_rfd, int ssl_wfd) { /* transfer data */

    fd_set rd_set, wr_set;
    int num, fdno, ssl_bytes, sock_bytes, retval;
    char sock_buff[BUFFSIZE], ssl_buff[BUFFSIZE];
    int sock_ptr, ssl_ptr, sock_rd, sock_wr, ssl_rd, ssl_wr;
    int check_SSL_pending;
    int ready;
    struct timeval tv;
#if defined FIONBIO && defined USE_NBIO
    unsigned long l;
#endif

    fdno=sock_rfd;
    if(sock_wfd>fdno) fdno=sock_wfd;
    if(ssl_rfd>fdno) fdno=ssl_rfd;
    if(ssl_wfd>fdno) fdno=ssl_wfd;
    fdno+=1;

    sock_ptr=ssl_ptr=0;
    sock_rd=sock_wr=ssl_rd=ssl_wr=1;
    sock_bytes=ssl_bytes=0;

#if defined FIONBIO && defined USE_NBIO
    log(LOG_DEBUG, "Seting sockets to non-blocking mode");
    l=1; /* ON */
    if(ioctlsocket(sock_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_rfd)"); /* non-critical */
    if(sock_wfd!=sock_rfd && ioctlsocket(sock_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_wfd)"); /* non-critical */
    if(ioctlsocket(ssl_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_rfd)"); /* non-critical */
    if(ssl_wfd!=ssl_rfd && ioctlsocket(ssl_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_wfd)"); /* non-critical */
    log(LOG_DEBUG, "Sockets set to non-blocking mode");
#endif

    while(((sock_rd||sock_ptr)&&ssl_wr)||((ssl_rd||ssl_ptr)&&sock_wr)) {

        FD_ZERO(&rd_set); /* Setup rd_set */
        if(sock_rd && sock_ptr<BUFFSIZE) /* socket input buffer not full*/
            FD_SET(sock_rfd, &rd_set);
        if(ssl_rd && (ssl_ptr<BUFFSIZE || /* SSL input buffer not full */
                (sock_ptr && SSL_want_read(ssl))
                /* I want to SSL_write but read from the underlying */
                /* socket needed for the SSL protocol */
                )) {
            FD_SET(ssl_rfd, &rd_set);
        }

        FD_ZERO(&wr_set); /* Setup wr_set */
        if(sock_wr && ssl_ptr) /* SSL input buffer not empty */
            FD_SET(sock_wfd, &wr_set);
        if (ssl_wr && (sock_ptr || /* socket input buffer not empty */
                (ssl_ptr<BUFFSIZE && SSL_want_write(ssl))
                /* I want to SSL_read but write to the underlying */
                /* socket needed for the SSL protocol */
                )) {
            FD_SET(ssl_wfd, &wr_set);
        }

        /* socket open for read -> set timeout to 1 hour */
        /* socket closed for read -> set timeout to 10 seconds */
        tv.tv_sec=sock_rd ? 3600 : 10;
        tv.tv_usec=0;

        do { /* Skip "Interrupted system call" errors */
            ready=select(fdno, &rd_set, &wr_set, NULL, &tv);
        } while(ready<0 && get_last_socket_error()==EINTR);
        if(ready<0) { /* Break the connection for others */
            sockerror("select");
            goto error;
        }
        if(!ready) { /* Timeout */
            if(sock_rd) { /* No traffic for a long time */
                log(LOG_DEBUG, "select timeout - connection reset");
                goto error;
            } else { /* Timeout waiting for SSL close_notify */
                log(LOG_DEBUG, "select timeout waiting for SSL close_notify");
                break; /* Leave the while() loop */
            }
        }

        /* Set flag to try and read any buffered SSL data if we made */
        /* room in the buffer by writing to the socket */
        check_SSL_pending = 0;

        if(sock_wr && FD_ISSET(sock_wfd, &wr_set)) {
            num=writesocket(sock_wfd, ssl_buff, ssl_ptr);
            if(num<0) {
                sockerror("write");
                goto error;
            }
            if(num) {
                memcpy(ssl_buff, ssl_buff+num, ssl_ptr-num);
                if(ssl_ptr==BUFFSIZE)
                    check_SSL_pending=1;
                ssl_ptr-=num;
                sock_bytes+=num;
                if(!ssl_rd && !ssl_ptr) {
                    shutdown(sock_wfd, SHUT_WR);
                    log(LOG_DEBUG,
                        "Socket write shutdown (no more data to send)");
                    sock_wr=0;
                }
            }
        }

        if(ssl_wr && ( /* SSL sockets are still open */
                (sock_ptr && FD_ISSET(ssl_wfd, &wr_set)) ||
                /* See if application data can be written */
                (SSL_want_read(ssl) && FD_ISSET(ssl_rfd, &rd_set))
                /* I want to SSL_write but read from the underlying */
                /* socket needed for the SSL protocol */
                )) {
            num=SSL_write(ssl, sock_buff, sock_ptr);

            switch(SSL_get_error(ssl, num)) {
            case SSL_ERROR_NONE:
                memcpy(sock_buff, sock_buff+num, sock_ptr-num);
                sock_ptr-=num;
                ssl_bytes+=num;
                if(!sock_rd && !sock_ptr && ssl_wr) {
                    SSL_shutdown(ssl); /* Send close_notify */
                    log(LOG_DEBUG,
                        "SSL write shutdown (no more data to send)");
                    ssl_wr=0;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
                log(LOG_DEBUG, "SSL_write returned WANT_ - retry");
                break;
            case SSL_ERROR_SYSCALL:
                if(num<0) { /* not EOF */
                    sockerror("SSL_write (ERROR_SYSCALL)");
                    goto error;
                }
                log(LOG_DEBUG, "SSL socket closed on SSL_write");
                ssl_rd=ssl_wr=0;
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify received */
                log(LOG_DEBUG, "SSL closed on SSL_write");
                ssl_rd=ssl_wr=0;
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_write");
                goto error;
            }
        }

        if(sock_rd && FD_ISSET(sock_rfd, &rd_set)) {
            num=readsocket(sock_rfd, sock_buff+sock_ptr, BUFFSIZE-sock_ptr);

            if(num<0 && get_last_socket_error()==ECONNRESET) {
                log(LOG_NOTICE, "IPC reset (child died)");
                break; /* close connection */
            }
            if (num<0 && get_last_socket_error()!=EIO) {
                sockerror("read");
                goto error;
            } else if (num>0) {
                sock_ptr += num;
            } else { /* close */
                log(LOG_DEBUG, "Socket closed on read");
                sock_rd=0;
                if(!sock_ptr && ssl_wr) {
                    SSL_shutdown(ssl); /* Send close_notify */
                    log(LOG_DEBUG,
                        "SSL write shutdown (output buffer empty)");
                    ssl_wr=0;
                }
            }
        }

        if(ssl_rd && ( /* SSL sockets are still open */
                (ssl_ptr<BUFFSIZE && FD_ISSET(ssl_rfd, &rd_set)) ||
                /* See if there's any application data coming in */
                (SSL_want_write(ssl) && FD_ISSET(ssl_wfd, &wr_set)) ||
                /* I want to SSL_read but write to the underlying */
                /* socket needed for the SSL protocol */
                (check_SSL_pending && SSL_pending(ssl))
                /* Write made space from full buffer */
                )) {
            num=SSL_read(ssl, ssl_buff+ssl_ptr, BUFFSIZE-ssl_ptr);

            switch(SSL_get_error(ssl, num)) {
            case SSL_ERROR_NONE:
                ssl_ptr+=num;
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
                log(LOG_DEBUG, "SSL_read returned WANT_ - retry");
                break;
            case SSL_ERROR_SYSCALL:
                if(num<0) { /* not EOF */
                    sockerror("SSL_read (SSL_ERROR_SYSCALL)");
                    goto error;
                }
                log(LOG_DEBUG, "SSL socket closed on SSL_read");
                ssl_rd=ssl_wr=0;
                break;
            case SSL_ERROR_ZERO_RETURN: /* close_notify received */
                log(LOG_DEBUG, "SSL closed on SSL_read");
                ssl_rd=0;
                if(!sock_ptr && ssl_wr) {
                    SSL_shutdown(ssl); /* Send close_notify back */
                    log(LOG_DEBUG,
                        "SSL write shutdown (output buffer empty)");
                    ssl_wr=0;
                }
                if(!ssl_ptr && sock_wr) {
                    shutdown(sock_wfd, SHUT_WR);
                    log(LOG_DEBUG,
                        "Socket write shutdown (output buffer empty)");
                    sock_wr=0;
                }
                break;
            case SSL_ERROR_SSL:
                sslerror("SSL_read");
                goto error;
            }
        }
    }
    retval=0;
    goto done;
error:
    retval=-1;
done:

#if defined FIONBIO && defined USE_NBIO
    log(LOG_DEBUG, "Seting sockets to blocking mode");
    l=0; /* OFF */
    if(sock_rd && ioctlsocket(sock_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_rfd)"); /* non-critical */
    if(sock_wr && sock_wfd!=sock_rfd && ioctlsocket(sock_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (sock_wfd)"); /* non-critical */
    if(ssl_rd && ioctlsocket(ssl_rfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_rfd)"); /* non-critical */
    if(ssl_wr && ssl_wfd!=ssl_rfd && ioctlsocket(ssl_wfd, FIONBIO, &l)<0)
        sockerror("ioctlsocket (ssl_wfd)"); /* non-critical */
    log(LOG_DEBUG, "Sockets back in blocking mode");
#endif

    log(LOG_NOTICE,
        "Connection %s: %d bytes sent to SSL, %d bytes sent to socket",
        retval<0 ? "reset" : "closed", ssl_bytes, sock_bytes);
    return retval;
}

static void print_cipher(SSL *ssl) { /* print negotiated cipher */
#if SSLEAY_VERSION_NUMBER > 0x0800
    SSL_CIPHER *c;
    char *ver;
    int bits;
#endif

#if SSLEAY_VERSION_NUMBER <= 0x0800
    log(LOG_INFO, "%s opened with SSLv%d, cipher %s",
        options.servname, ssl->session->ssl_version, SSL_get_cipher(ssl));
#else
    switch(ssl->session->ssl_version) {
    case SSL2_VERSION:
        ver="SSLv2"; break;
    case SSL3_VERSION:
        ver="SSLv3"; break;
    case TLS1_VERSION:
        ver="TLSv1"; break;
    default:
        ver="UNKNOWN";
    }
    c=SSL_get_current_cipher(ssl);
    SSL_CIPHER_get_bits(c, &bits);
    log(LOG_INFO, "%s opened with %s, cipher %s (%u bits)",
        options.servname, ver, SSL_CIPHER_get_name(c), bits);
#endif
}

static int auth_user(struct sockaddr_in *addr) {
    struct servent *s_ent;    /* structure for getservbyname */
    struct sockaddr_in ident; /* IDENT socket name */
    int fd;                   /* IDENT socket descriptor */
    char name[STRLEN];
    int retval;
    unsigned long l;

    if(!options.username)
        return 0; /* -u option not specified */
    if((fd=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket (auth_user)");
        return -1;
    }
    l=1; /* ON */
    if(ioctlsocket(fd, FIONBIO, &l)<0)
        sockerror("ioctlsocket(FIONBIO)"); /* non-critical */
    memcpy(&ident, addr, sizeof(ident));
    s_ent=getservbyname("auth", "tcp");
    if(!s_ent) {
        log(LOG_WARNING, "Unknown service 'auth' - using default 113");
        ident.sin_port=htons(113);
    } else {
        ident.sin_port=s_ent->s_port;
    }
    if(connect(fd, (struct sockaddr *)&ident, sizeof(ident))<0) {
        if(get_last_socket_error()==EINPROGRESS) {
            switch(waitforsocket(fd, 1 /* write */)) {
            case -1: /* Error */
                sockerror("select");
                return -1;
            case 0: /* Timeout */
                log(LOG_ERR, "Select timeout (auth_user)");
                return -1;
            }
            if(connect(fd, (struct sockaddr *)&ident, sizeof(ident))<0) {
                sockerror("connect#2 (auth_user))");
                closesocket(fd);
                return -1;
            }
            log(LOG_DEBUG, "IDENT server connected (#2)");
        } else {
            sockerror("connect#1 (auth_user)");
            closesocket(fd);
            return -1;
        }
    } else
        log(LOG_DEBUG, "IDENT server connected (#1)");
    if(fdprintf(fd, "%u , %u",
            ntohs(addr->sin_port), ntohs(options.localport))<0) {
        sockerror("fdprintf (auth_user)");
        closesocket(fd);
        return -1;
    }
    if(fdscanf(fd, "%*[^:]: USERID :%*[^:]:%s", name)!=1) {
        log(LOG_ERR, "Incorrect data from IDENT server");
        closesocket(fd);
        return -1;
    }
    closesocket(fd);
    retval=strcmp(name, options.username) ? -1 : 0;
    safestring(name);
    log(LOG_INFO, "IDENT resolved remote user to %s", name);
    return retval;
}

static int connect_local(u32 ip) { /* spawn local process */
#ifdef USE_WIN32
    log(LOG_ERR, "LOCAL MODE NOT SUPPORTED ON WIN32 PLATFORM");
    return -1;
#else
    struct in_addr addr;
    char text[STRLEN];
    int fd[2];
    unsigned long pid;

    if (options.option & OPT_PTY) {
        char tty[STRLEN];

        if(pty_allocate(fd, fd+1, tty, STRLEN)) {
            return -1;
        }
        log(LOG_DEBUG, "%s allocated", tty);
    } else {
        if(make_sockets(fd))
            return -1;
    }
#ifdef USE_FORK
    /* Each child has to take care of its own dead children */
    signal(SIGCHLD, local_handler);
#endif /* defined USE_FORK */
    /* With USE_PTHREAD main thread does the work */
    /* and SIGCHLD is blocked in other theads */
    pid=(unsigned long)fork();
    switch(pid) {
    case -1:    /* error */
        closesocket(fd[0]);
        closesocket(fd[1]);
        ioerror("fork");
        return -1;
    case  0:    /* child */
        closesocket(fd[0]);
        dup2(fd[1], 0);
        dup2(fd[1], 1);
        if (!options.foreground)
            dup2(fd[1], 2);
        closesocket(fd[1]);
        if (ip) {
            putenv("LD_PRELOAD=" libdir "/stunnel.so");
            /* For Tru64 _RLD_LIST is used instead */
            putenv("_RLD_LIST=" libdir "/stunnel.so:DEFAULT");
            addr.s_addr = ip;
            safecopy(text, "REMOTE_HOST=");
            enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
            safeconcat(text, inet_ntoa(addr));
            leave_critical_section(CRIT_NTOA);
            putenv(text);
        }
        execvp(options.execname, options.execargs);
        ioerror(options.execname); /* execv failed */
        _exit(1);
    }
    /* parent */
    log(LOG_INFO, "Local mode child started (PID=%lu)", pid);
    closesocket(fd[1]);
    return fd[0];
#endif /* USE_WIN32 */
}

#ifndef USE_WIN32
static int make_sockets(int fd[2]) { /* make pair of connected sockets */
#ifdef INET_SOCKET_PAIR
    struct sockaddr_in addr;
    int addrlen;
    int s; /* temporary socket awaiting for connection */

    if((s=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket#1");
        return -1;
    }
    if((fd[1]=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("socket#2");
        return -1;
    }
    addrlen=sizeof(addr);
    memset(&addr, 0, addrlen);
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    addr.sin_port=0; /* dynamic port allocation */
    if(bind(s, (struct sockaddr *)&addr, addrlen))
        log(LOG_DEBUG, "bind#1: %s (%d)",
            strerror(get_last_socket_error()), get_last_socket_error());
    if(bind(fd[1], (struct sockaddr *)&addr, addrlen))
        log(LOG_DEBUG, "bind#2: %s (%d)",
            strerror(get_last_socket_error()), get_last_socket_error());
    if(listen(s, 5)) {
        sockerror("listen");
        return -1;
    }
    if(getsockname(s, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("getsockname");
        return -1;
    }
    if(connect(fd[1], (struct sockaddr *)&addr, addrlen)) {
        sockerror("connect");
        return -1;
    }
    if((fd[0]=accept(s, (struct sockaddr *)&addr, &addrlen))<0) {
        sockerror("accept");
        return -1;
    }
    closesocket(s); /* don't care about the result */
#else
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
        sockerror("socketpair");
        return -1;
    }
#endif
    return 0;
}
#endif

static int connect_remote(u32 ip) { /* connect to remote host */
    struct sockaddr_in addr;
    int s; /* destination socket */
    u32 *list; /* destination addresses list */

    if((s=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("remote socket");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;

    if(ip) { /* transparent proxy */
        addr.sin_addr.s_addr=ip;
        addr.sin_port=htons(0);
        if(bind(s, (struct sockaddr *)&addr, sizeof(addr))<0) {
            sockerror("bind transparent");
            return -1;
        }
    }

    addr.sin_port=options.remoteport;

    /* connect each host from the list */
    for(list=options.remotenames; *list!=-1; list++) {
        addr.sin_addr.s_addr=*list;
        enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
        log(LOG_DEBUG, "%s connecting %s:%d", options.servname,
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        leave_critical_section(CRIT_NTOA);
        if(!connect(s, (struct sockaddr *) &addr, sizeof(addr)))
            return s; /* success */
    }
    sockerror("remote connect");
    return -1;
}

int fdprintf(int fd, char *format, ...) {
    va_list arglist;
    char line[STRLEN], logline[STRLEN];
    char crlf[]="\r\n";
    int len, ptr, written, towrite;

    va_start(arglist, format);
#ifdef HAVE_VSNPRINTF
    len=vsnprintf(line, STRLEN, format, arglist);
#else
    len=vsprintf(line, format, arglist);
#endif
    va_end(arglist);
    safeconcat(line, crlf);
    len+=2;
    for(ptr=0, towrite=len; towrite>0; ptr+=written, towrite-=written) {
        switch(waitforsocket(fd, 1 /* write */)) {
        case -1: /* Error */
            sockerror("select");
            return -1;
        case 0: /* Timeout */
            log(LOG_ERR, "Select timeout (fdprintf)");
            return -1;
        }
        written=writesocket(fd, line+ptr, towrite);
        if(written<0) {
            sockerror("writesocket (fdprintf)");
            return -1;
        }
    }
    safecopy(logline, line);
    safestring(logline);
    log(LOG_DEBUG, " -> %s", logline);
    return len;
}

int fdscanf(int fd, char *format, char *buffer) {
    char line[STRLEN], logline[STRLEN];
    int ptr;

    for(ptr=0; ptr<STRLEN-1; ptr++) {
        switch(waitforsocket(fd, 0 /* read */)) {
        case -1: /* Error */
            sockerror("select");
            return -1;
        case 0: /* Timeout */
            log(LOG_ERR, "Select timeout (fdscanf)");
            return -1;
        }
        switch(readsocket(fd, line+ptr, 1)) {
        case -1: /* error */
            sockerror("readsocket (fdscanf)");
            return -1;
        case 0: /* EOF */
            log(LOG_ERR, "Unexpected socket close (fdscanf)");
            return -1;
        }
        if(line[ptr]=='\r')
            continue;
        if(line[ptr]=='\n')
            break;
    }
    line[ptr]='\0';
    safecopy(logline, line);
    safestring(logline);
    log(LOG_DEBUG, " <- %s", logline);
    return sscanf(line, format, buffer);
}

static int waitforsocket(int fd, int dir) {
    /* dir: 0 for read, 1 for write */
    struct timeval tv;
    fd_set set;
    int ready;

    tv.tv_sec=60; /* One minute */
    tv.tv_usec=0;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    do { /* Skip "Interrupted system call" errors */
        ready=select(fd+1, dir ? NULL : &set, dir ? &set : NULL, NULL, &tv);
    } while(ready<0 && get_last_socket_error()==EINTR);
    return ready;
}

/* End of client.c */
