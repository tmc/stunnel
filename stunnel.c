/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (c) 1998-2001 Michal Trojnara <Michal.Trojnara@mirt.net>
 *                 All Rights Reserved
 *
 *   Version:      3.21                  (stunnel.c)
 *   Date:         2001.09.xx
 *
 *   Author:       Michal Trojnara  <Michal.Trojnara@mirt.net>
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

#include "common.h"
#include "prototypes.h"

#ifdef USE_WIN32
static struct WSAData wsa_state;
#endif

    /* Prototypes */
static void daemon_loop();
#ifndef USE_WIN32
static void daemonize();
static void create_pid();
static void delete_pid();
#endif

    /* Socket functions */
static int listen_local();

    /* Error/exceptions handling functions */
void ioerror(char *);
void sockerror(char *);
#ifdef USE_FORK
static void sigchld_handler(int);
#endif
#ifndef USE_WIN32
static void signal_handler(int);
#endif

server_options options;

    /* Functions */
int main(int argc, char* argv[]) { /* execution begins here 8-) */
    struct stat st; /* buffer for stat */

#ifdef USE_WIN32
    if(WSAStartup(0x0101, &wsa_state)!=0) {
        sockerror("WSAStartup");
        exit(1);
    }
#else
    signal(SIGPIPE, SIG_IGN); /* avoid 'broken pipe' signal */
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    /* signal(SIGSEGV, signal_handler); */
#endif

    /* process options */
    options.foreground=1;
    options.cert_defaults=CERT_DEFAULTS;

    safecopy(options.pem, PEM_DIR);
    if(options.pem[0]) /* not an empty string */
        safeconcat(options.pem, "/");
    safeconcat(options.pem, "stunnel.pem");

    parse_options(argc, argv);
    if(!(options.option&OPT_FOREGROUND))
        options.foreground=0;
    log_open();
    log(LOG_NOTICE, "Using '%s' as tcpwrapper service name", options.servname);

    /* check if certificate exists */
    if(options.option&OPT_CERT) {
        if(stat(options.pem, &st)) {
            ioerror(options.pem);
            exit(1);
        }
#ifndef USE_WIN32
        if(st.st_mode & 7)
            log(LOG_WARNING, "Wrong permissions on %s", options.pem);
#endif /* defined USE_WIN32 */
    }

    /* check if started from inetd */
    context_init(); /* initialize global SSL context */
    sthreads_init(); /* initialize threads */
    log(LOG_NOTICE, "%s", STUNNEL_INFO);
    if(options.option & OPT_DAEMON) { /* daemon mode */
#ifndef USE_WIN32
        if(!(options.option & OPT_FOREGROUND))
            daemonize();
        create_pid();
#endif
        daemon_loop();
    } else { /* inetd mode */
        options.clients = 1;
        client((void *)STDIO_FILENO); /* rd fd=0, wr fd=1 */
    }
    /* close SSL */
    context_free(); /* free global SSL context */
    log_close();
    return 0; /* success */
}

static void daemon_loop() {
    int ls, s;
    struct sockaddr_in addr;
    int addrlen;

    ls=listen_local();
    options.clients=0;
#ifndef USE_WIN32
#ifdef USE_FORK
    /* Handle signals about dead children */
    signal(SIGCHLD, sigchld_handler);
#else /* defined USE_FORK */
    /* Ignore signals about dead children of clients' threads */
    signal(SIGCHLD, SIG_IGN);
#endif /* defined USE_FORK */
#endif /* ndefined USE_WIN32 */
    while(1) {
        addrlen=sizeof(addr);
        do {
            s=accept(ls, (struct sockaddr *)&addr, &addrlen);
        } while(s<0 && get_last_socket_error()==EINTR);
        if(s<0) {
            sockerror("accept");
            sleep(10);
            continue;
        }
#ifdef FD_CLOEXEC
        fcntl(s, F_SETFD, FD_CLOEXEC); /* close socket in child execvp */
#endif
        if(options.clients<MAX_CLIENTS) {
            if(create_client(ls, s, client)) {
                enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
                log(LOG_WARNING,
                    "%s create_client failed - connection from %s:%d REJECTED",
                    options.servname,
                    inet_ntoa(addr.sin_addr),
                    ntohs(addr.sin_port));
                leave_critical_section(CRIT_NTOA);
            } else {
                enter_critical_section(CRIT_CLIENTS); /* for multi-cpu machines */
                options.clients++;
                leave_critical_section(CRIT_CLIENTS);
            }
        } else {
            enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
            log(LOG_WARNING,
                "%s has too many clients - connection from %s:%d REJECTED",
                options.servname, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            leave_critical_section(CRIT_NTOA);
            closesocket(s);
        }
    }
}

#ifndef USE_WIN32
static void daemonize() { /* go to background */
#ifdef HAVE_DAEMON
    if(daemon(0,0)==-1){
        ioerror("daemon");
        exit(1);
    }
#else
    chdir("/");
    switch(fork()) {
    case -1:    /* fork failed */
        ioerror("fork");
        exit(1);
    case 0:     /* child */
        break;
    default:    /* parent */
        exit(0);
    }
    if (setsid() == -1) {
        ioerror("setsid");
        exit(1);
    }
    close(0);
    close(1);
    close(2);
#endif
}

static void create_pid() {
    int pf;
    char pid[STRLEN];
    struct stat sb;
    int force_dir;
    char tmpdir[STRLEN];

    safecopy(tmpdir, options.pid_dir);

    if(strcmp(tmpdir, "none") == 0) {
        log(LOG_DEBUG, "No pid file being created");
        options.pidfile[0]='\0';
        return;
    }
    if(!strchr(tmpdir, '/')) {
        log(LOG_ERR, "Argument to -P (%s) must be full path name",
            tmpdir);
        /* Why?  Because we don't want to confuse by
           allowing '.', which would be '/' after
           daemonizing) */
        exit(1);
    }
    options.dpid=(unsigned long)getpid();

    /* determine if they specified a pid dir or pid file,
       and set our options.pidfile appropriately */
    if(tmpdir[strlen(tmpdir)-1] == '/' ) {
        force_dir=1; /* user requested -P argument to be a directory */
        tmpdir[strlen(tmpdir)-1] = '\0';
    } else {
        force_dir=0; /* this can be either a file or a directory */
    }
    if(!stat(tmpdir, &sb) && S_ISDIR(sb.st_mode)) { /* directory */
#ifdef HAVE_SNPRINTF
        snprintf(options.pidfile, STRLEN,
            "%s/stunnel.%s.pid", tmpdir, options.servname);
#else /* No data from network here.  Am I paranoid? */
        safecopy(options.pidfile, tmpdir);
        safeconcat(options.pidfile, "/stunnel.");
        safeconcat(options.pidfile, options.servname);
        safeconcat(options.pidfile, ".pid");
#endif
    } else { /* file */
        if(force_dir) {
            log(LOG_ERR, "Argument to -P (%s/) is not valid a directory name",
                tmpdir);
            exit(1);
        }
        safecopy(options.pidfile, tmpdir);
    }

    /* silently remove old pid file */
    unlink(options.pidfile);
    if (-1==(pf=open(options.pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL,0644))) {
        log(LOG_ERR, "Cannot create pid file %s", options.pidfile);
        ioerror("create");
        exit(1);
    }
    sprintf(pid, "%lu", options.dpid);
    write( pf, pid, strlen(pid) );
    close(pf);
    log(LOG_DEBUG, "Created pid file %s", options.pidfile);
    atexit(delete_pid);
}

static void delete_pid() {
    log(LOG_DEBUG, "removing pid file %s", options.pidfile);
    if((unsigned long)getpid()!=options.dpid)
        return; /* Current process is not main daemon process */
    if(unlink(options.pidfile)<0)
        ioerror(options.pidfile); /* not critical */
}
#endif /* defined USE_WIN32 */

static int listen_local() { /* bind and listen on local interface */
    struct sockaddr_in addr;
    int ls;

    if((ls=socket(AF_INET, SOCK_STREAM, 0))<0) {
        sockerror("local socket");
        exit(1);
    }
    if(set_socket_options(ls, 0)<0)
        exit(1);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=*options.localnames;
    addr.sin_port=options.localport;
    if(bind(ls, (struct sockaddr *)&addr, sizeof(addr))) {
        sockerror("bind");
        exit(1);
    }
    enter_critical_section(CRIT_NTOA); /* inet_ntoa is not mt-safe */
    log(LOG_DEBUG, "%s bound to %s:%d", options.servname,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    leave_critical_section(CRIT_NTOA);
    if(listen(ls, 5)) {
        sockerror("listen");
        exit(1);
    }

#ifndef USE_WIN32
    if(options.setgid_group) {
        struct group *gr;
        gid_t gr_list[1];

        gr=getgrnam(options.setgid_group);
        if(!gr) {
            log(LOG_ERR, "Failed to get GID for group %s",
                options.setgid_group);
            exit(1);
        }
        if(setgid(gr->gr_gid)) {
            sockerror("setgid");
            exit(1);
        }
        gr_list[0]=gr->gr_gid;
        if(setgroups(1, gr_list)) {
            sockerror("setgroups");
            exit(1);
        }
    }

    if(options.setuid_user) {
        struct passwd *pw;

        pw=getpwnam(options.setuid_user);
        if(!pw) {
            log(LOG_ERR, "Failed to get UID for user %s",
                options.setuid_user);
            exit(1);
        }
#ifndef USE_WIN32
        /* gotta chown that pid file, or we can't remove it. */
        if ( options.pidfile[0] && chown( options.pidfile, pw->pw_uid, -1) ) {
            log(LOG_ERR, "Failed to chown pidfile %s", options.pidfile);
        }
#endif
        if(setuid(pw->pw_uid)) {
            sockerror("setuid");
            exit(1);
        }
    }
#endif /* USE_WIN32 */

    return ls;
}

int set_socket_options(int s, int type) {
    sock_opt *ptr;
    extern sock_opt sock_opts[];
    static char *type_str[3]={"accept", "local", "remote"};
    int opt_size;

    for(ptr=sock_opts;ptr->opt_str;ptr++) {
        if(!ptr->opt_val[type])
            continue; /* default */
        switch(ptr->opt_type) {
        case TYPE_LINGER:
            opt_size=sizeof(struct linger); break;
        case TYPE_TIMEVAL:
            opt_size=sizeof(struct timeval); break;
        case TYPE_STRING:
            opt_size=strlen(ptr->opt_val[type]->c_val)+1; break;
        default:
            opt_size=sizeof(int); break;
        }
        if(setsockopt(s, ptr->opt_level, ptr->opt_name,
                (void *)ptr->opt_val[type], opt_size)) {
            sockerror(ptr->opt_str);
            return -1; /* FAILED */
        } else {
            log(LOG_DEBUG, "%s option set on %s socket",
                ptr->opt_str, type_str[type]);
        }
    }
    return 0; /* OK */
}

void ioerror(char *txt) { /* Input/Output error handler */
    int error;

    error=get_last_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

void sockerror(char *txt) { /* Socket error handler */
    int error;

    error=get_last_socket_error();
    log(LOG_ERR, "%s: %s (%d)", txt, strerror(error), error);
}

#ifdef USE_FORK
static void sigchld_handler(int sig) { /* Dead children detected */
    int pid, status;

#ifdef HAVE_WAIT_FOR_PID
    while((pid=wait_for_pid(-1, &status, WNOHANG))>0) {
        options.clients--; /* One client less */
#else
    pid=wait(&status);
    options.clients--; /* One client less */
    {
#endif
#ifdef WIFSIGNALED
        if(WIFSIGNALED(status)) {
            log(LOG_DEBUG, "%s[%d] terminated on signal %d (%d left)",
                options.servname, pid, WTERMSIG(status), options.clients);
        } else {
            log(LOG_DEBUG, "%s[%d] finished with code %d (%d left)",
                options.servname, pid, WEXITSTATUS(status), options.clients);
        }
    }
#else
        log(LOG_DEBUG, "%s[%d] finished with code %d (%d left)",
            options.servname, pid, status, options.clients);
    }
#endif
    signal(SIGCHLD, sigchld_handler);
}
#endif

#ifndef USE_WIN32

static void signal_handler(int sig) { /* Signal handler */
    log(LOG_ERR, "Received signal %d; terminating", sig);
    exit(3);
}

#endif /* !defined USE_WIN32 */

/* End of stunnel.c */
