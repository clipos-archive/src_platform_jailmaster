// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/*
 * jail.c - jailmaster implementation.
 *
 * Copyright (C) 2005-2009 SGDN/DCSSI
 * Copyright (C) 20013 SGDSN/ANSSI
 * Authors: 	Olivier Grumelard <clipos@ssi.gouv.fr>
 * 		Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef JAILMASTER_SYSLOG
#include <syslog.h>
#endif
#include <arpa/inet.h>

#include <clip.h>

#include "jail.h"

#define USER_SESSION_SCRIPT "/usr/local/bin/user-session.sh"
#define UPDATE_SERVICE "/sbin/update-service"

#ifdef JAILMASTER_SYSLOG
#define ERROR(fmt, args...) \
	syslog(LOG_DAEMON|LOG_ERR, "%s: " fmt, __FUNCTION__, ##args)

#define INFO(fmt, args...) \
	syslog(LOG_DAEMON|LOG_INFO, "%s: " fmt, __FUNCTION__, ##args)

#define PERROR(msg) \
	syslog(LOG_DAEMON|LOG_ERR, "%s: " msg ": %s", __FUNCTION__, \
			strerror(errno))

#else
#define ERROR(fmt, args...) \
	fprintf(stderr, "%s: error: " fmt, __FUNCTION__, ##args)

#define INFO(fmt, args...) \
	fprintf(stderr, "%s: " fmt, __FUNCTION__, ##args)

#define PERROR(msg) perror(msg)
#endif


static int user_exec(int s)
{
	uid_t uid;
	gid_t gid;
	const char *sess;
	struct passwd *user_pwd;
	static char *argv[] = {
		NULL,
		NULL
	};
	static char *envp[] = {
		NULL,	/* "USER=..." */
		NULL,	/* "HOME=..." */
		NULL,	/* "LOCAL_ADDR=..."*/
		NULL
	};
	char *user = NULL; 
	char *home = NULL;
	char *addr = NULL; 
	char *tmp =NULL;

	if (setsid() < 0) {
		PERROR("setsid");
		goto out;
	}
	/* Policy: drop supplementary groups and take caller uid/gid */
	if (clip_getpeereid(s, &uid, &gid) < 0) {
/* Use getsockopt(s, 0, LOCAL_PEERCRED, ...) if need suppl. groups */
		PERROR("getpeereid");
		goto out;
	}
	/* Drop privileges before parsing input... */
	if (setgid(gid)) {
		PERROR("setgid");
		goto out;
	}

	user_pwd = getpwuid(uid);
	if (user_pwd == NULL) {
		PERROR("getpwuid");
		goto out;
	}

	if (initgroups(user_pwd->pw_name, gid)) {
		PERROR("initgroups");
		goto out;
	}

	if (setuid(uid)) {
		PERROR("setuid");
		goto out;
	}
	user = malloc(strlen(user_pwd->pw_name) + sizeof("USER="));
	if (!user) {
		PERROR("malloc");
		goto out;
	}
	sprintf(user, "USER=%s", user_pwd->pw_name);
	envp[0] = user;
	home = malloc(strlen(user_pwd->pw_dir) + sizeof("HOME="));
	if (!home) {
		PERROR("malloc");
		goto out;
	}
	sprintf(home, "HOME=%s", user_pwd->pw_dir);
	envp[1] = home;

	tmp = getenv("LOCAL_ADDR");
	if (tmp) {
		addr = malloc(strlen(tmp) + sizeof("LOCAL_ADDR="));
		if (!addr) {
			PERROR("malloc");
			goto out;
		}
		sprintf(addr, "LOCAL_ADDR=%s", tmp);
		envp[2] = addr;
	}

	argv[0] = USER_SESSION_SCRIPT;
	sess = "user session";

	close(s);
	s = -1;
	INFO("opening %s for %s", sess, user_pwd->pw_name);
	execve(argv[0], argv, envp);

/* Fallback on failure */
	PERROR("execve");
	
out:
	if (addr) free(addr);
	if (home) free(home);
	if (user) free(user);

	if (s>=0)
		close(s);
	return -1;
}

static int user_service(void)
{
	int s, s_com, status;
	pid_t f, wret;
	socklen_t len;
	struct sockaddr_un sau;

	/* We will write to a socket that may be closed on client-side, and
	   we don't want to die... We don't need to warn our children as they
	   will notice if Xnest closes its own listening socket. */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		PERROR("signal");
		return 1;
	}
	
	s = clip_sock_listen("/var/run/start", &sau, 0);

	if (s < 0) {
		return 1;
	}

	for (;;) {
		len = sizeof(struct sockaddr_un);
		s_com = accept(s, (struct sockaddr *)&sau, &len);
		if (s_com < 0) {
			PERROR("accept");
			close(s);
			return 1;
		}
		f = fork();
		if (f < 0) {
			PERROR("fork");
			close(s_com);
			continue;
		} else if (f > 0) {
			/* Father */
			wret = waitpid(f, &status, 0);
			if (wret < 0) {
				PERROR("waitpid");
				if(write(s_com, "N", 1) < 0)
					PERROR("write N");
				/* Lost child ? */
			} else {
				if (write(s_com, "Y", 1) < 0)
					PERROR("write Y");
			}
			close(s_com);
			continue;
		} else {
			/* Child */
			close(s);
			exit(user_exec(s_com));
		}
	}
}

static int update_service(void)
{
	char *argv[] = { UPDATE_SERVICE, NULL };
	char *envp[] = { NULL };
	return -execve(argv[0], argv, envp);
}

int start_jail(void)
{
	int wret, status;
	pid_t update, user;

	if (clip_daemonize()) {
		PERROR("clip_fork");
		return 1;
	}

#ifdef JAILMASTER_SYSLOG
	openlog("jailmaster", LOG_PID, LOG_DAEMON);
#endif
	
	update = fork();
	if (update < 0) {
		PERROR("fork");
		return 1;
	} else if (update == 0) {
		if (clip_chroot("/update")) {
			PERROR("chroot /update");
			exit(1);
		}
		exit(update_service());
	}
	wret = waitpid(update, &status, 0);
	if (wret < 0) {
		PERROR("waitpid");
		/* Lost child ? */
	}

	user = fork();
	if (user < 0) {
		PERROR("fork");
		return 1;
	} else if (user == 0) {
		if (clip_chroot("/user")) {
			PERROR("chroot /user");
			exit(1);
		}
		exit(user_service());
	}

	return 0;
}
