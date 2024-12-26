/**
 * pam_dumb_runtime_dir.c
 *
 * Creates an XDG_RUNTIME_DIR directory on login per the freedesktop.org
 * base directory spec. Flaunts the spec and never removes it, even after
 * last logout. This keeps things simple and predictable.
 *
 * Copyright 2021 Isaac Freund
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <security/pam_modules.h>

static int mkdir_ensureperms(const char *path, mode_t mode, uid_t uid, gid_t gid) {
	if (mkdir(path, mode) < 0) {
		/* It's ok if the directory already exists, in that case we just
		 * ensure the mode is correct before we chown(). */
		if (!(errno == EEXIST && chmod(path, mode) == 0)) {
			return -1;
		}
	}
	return chown(path, uid, gid);
}

int pam_sm_open_session(pam_handle_t *pamh, int flags,
		int argc, const char **argv) {
	(void)flags;
	(void)argc;
	(void)argv;

	const char *user;
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
		return PAM_SESSION_ERR;
	}

	struct passwd *pw = getpwnam(user);
	if (pw == NULL) {
		return PAM_SESSION_ERR;
	}

	/* The bit size of uintmax_t will always be larger than the number of
	 * bytes needed to print it. */
	char buffer[sizeof("XDG_RUNTIME_DIR="RUNTIME_DIR_PARENT"/") +
		sizeof(uintmax_t) * 8];
	/* Valid UIDs are always positive even if POSIX allows the uid_t type
	 * itself to be signed. Therefore, we can convert to uintmax_t for
	 * safe formatting. */
	int ret = snprintf(buffer, sizeof(buffer),
		"XDG_RUNTIME_DIR="RUNTIME_DIR_PARENT"/%ju", (uintmax_t)pw->pw_uid);
	assert(ret >= 0 && (size_t)ret < sizeof(buffer));
	const char *path = buffer + sizeof("XDG_RUNTIME_DIR=") - 1;

	const mode_t oldmask = umask(S_IWGRP | S_IWOTH);
	/* see kernel source include/linux/uidgid.h: uid and gid 0 are
	 * guaranteed to be root */
	ret = mkdir_ensureperms(RUNTIME_DIR_PARENT, 0755, 0, 0) == 0
		&& mkdir_ensureperms(path, 0700, pw->pw_uid, pw->pw_gid) == 0;
	umask(oldmask);
	if (!ret) {
		return PAM_SESSION_ERR;
	}

	if (pam_putenv(pamh, buffer) != PAM_SUCCESS) {
		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}

/* PAM requires all functions in a group to be defined, even if a noop is
 * desired. Otherwise, PAM_MODULE_UNKNOWN is returned when the application
 * calls pam_close_session(3). */
int pam_sm_close_session(pam_handle_t *pamh, int flags,
		int argc, const char **argv) {
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}
