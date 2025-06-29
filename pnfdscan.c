/*
 * dosattrib.c
 *
 * Copyright (c) 2025 Peter Eriksson <pen@lysator.liu.se>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _XOPEN_SOURCE 700
#define X_POSIX_C_SOURCE 200809L

#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <ftw.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unicode/utypes.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>



char *argv0 = "pnfdscan";

int f_verbose = 0;
int f_debug = 0;
int f_update = 1;
int f_autofix = 0;
int f_remove = 0;
int f_ignore = 0;
int f_mount = 0;

unsigned long n_ascii = 0;
unsigned long n_nfd = 0;
unsigned long n_nfc = 0;
unsigned long n_other = 0;
unsigned long n_unknown = 0;
unsigned long n_coll = 0;
unsigned long n_objects = 0;
unsigned long n_unread = 0;
unsigned long n_renamed = 0;
unsigned long n_removed = 0;

const UNormalizer2 *nfd;
const UNormalizer2 *nfc;



typedef enum {
    ACT_RENAME_NFD = 1,
    ACT_REMOVE_NFD = 2,
    ACT_REMOVE_NFC = 3,
} ACTION_TYPE;


typedef struct action {
    ACTION_TYPE type;
    char *dir;
    struct {
	struct stat sb;
	char *name;
    } nfd, nfc;
    struct action *next;
} ACTION;

unsigned long n_actions = 0;
ACTION *actions = NULL;


void
add_action(char *dir,
	   const struct stat *nfd_sp,
	   const char *nfd_name,
	   const struct stat *nfc_sp,
	   const char *nfc_name,
	   int type) {
    ACTION *ap = malloc(sizeof(*ap));

    if (!ap)
        abort();

    memset(ap, 0, sizeof(*ap));

    ap->type = type;
    ap->dir = dir;
    
    ap->nfd.sb = *nfd_sp;
    ap->nfd.name = strdup(nfd_name);
    
    if (nfc_sp)
        ap->nfc.sb = *nfc_sp;
    if (nfc_name)
        ap->nfc.name = strdup(nfc_name);

    ap->next = actions;
    actions = ap;

    n_actions++;
}


void
setup(void) {
    UErrorCode status = U_ZERO_ERROR;

    nfd = unorm2_getInstance(NULL, "nfc", UNORM2_DECOMPOSE, &status);
    nfc = unorm2_getInstance(NULL, "nfc", UNORM2_COMPOSE, &status);

    if (U_FAILURE(status)) {
        fprintf(stderr, "Failed to get normalization instance: %s\n", u_errorName(status));
        return;
    }
}


char *
time2str(time_t t,
	 char *buf,
	 size_t bufsize) {
    struct tm *tp;

    tp = localtime(&t);
    strftime(buf, bufsize, "%Y-%m-%d %H:%M:%S", tp);
    return buf;
}


int
utf8_to_utf16(const char *utf8_input,
	      UChar utf16_input[8192],
	      int32_t *utf16_len) {
    UErrorCode status = U_ZERO_ERROR;

    u_strFromUTF8(utf16_input, 8192, utf16_len, utf8_input, -1, &status);
    if (U_FAILURE(status)) {
        fprintf(stderr, "UTF-8 to UTF-16 conversion failed: %s\n", u_errorName(status));
        return -1;
    }

    return 0;
}

char *
dirname(const char *path,
	const char **name) {
    char *cp;
    size_t len;

    cp = strrchr(path, '/');
    if (!cp) {
        if (name)
            *name = path;

        return strdup(".");
    }

    len = cp-path;
    if (name)
        *name = cp+1;

    return strndup(path, len);

}

int
is_nfd(UChar utf16_input[8192],
       int32_t utf16_len) {
    UErrorCode status = U_ZERO_ERROR;
    UBool r;

    r = unorm2_isNormalized(nfd, utf16_input, utf16_len, &status);
    if (U_FAILURE(status)) {
        fprintf(stderr, "NFD Normalization check failed: %s\n", u_errorName(status));
        return -1;
    }

    return r;
}



int
is_nfc(UChar utf16_input[8192],
       int32_t utf16_len) {
    UErrorCode status = U_ZERO_ERROR;
    UBool r;

    r = unorm2_isNormalized(nfc, utf16_input, utf16_len, &status);
    if (U_FAILURE(status)) {
        fprintf(stderr, "NFC Normalization check failed: %s\n", u_errorName(status));
        return -1;
    }

    return r;
}




int
to_nfc(UChar utf16_input[8192],
       int32_t utf16_len,
       char utf8_output[8192],
       int32_t *utf8_output_len) {
    UErrorCode status = U_ZERO_ERROR;
    UChar utf16_output[8192];
    int32_t output_len;

    output_len = unorm2_normalize(nfc, utf16_input, utf16_len, utf16_output, 8192, &status);
    if (U_FAILURE(status)) {
        fprintf(stderr, "Normalization to NFC failed: %s\n", u_errorName(status));
        return -1;
    }

    // Convert UTF-16 back to UTF-8
    u_strToUTF8(utf8_output, 8192, utf8_output_len, utf16_output, output_len, &status);
    if (U_FAILURE(status)) {
        fprintf(stderr, "UTF-16 to UTF-8 conversion failed: %s\n", u_errorName(status));
        return -1;
    }

    return 0;
}


int
is_ascii(const char *s) {
    while (*s) {
        if (!isascii(*s))
            return 0;
        s++;
    }
    return 1;
}


int
is_valid_utf8(const char *str) {
    const unsigned char *bytes = (const unsigned char *)str;

    while (*bytes) {
        if (*bytes <= 0x7F) {
            // ASCII
            bytes += 1;
        } else if ((*bytes & 0xE0) == 0xC0) {
            // 2-byte sequence
            if ((bytes[1] & 0xC0) != 0x80) return 0;
            if (*bytes < 0xC2) return 0; // Overlong encoding
            bytes += 2;
        } else if ((*bytes & 0xF0) == 0xE0) {
            // 3-byte sequence
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80) return 0;
            if (*bytes == 0xE0 && bytes[1] < 0xA0) return 0; // Overlong
            if (*bytes == 0xED && bytes[1] >= 0xA0) return 0; // Surrogates
            bytes += 3;
        } else if ((*bytes & 0xF8) == 0xF0) {
            // 4-byte sequence
            if ((bytes[1] & 0xC0) != 0x80 ||
                (bytes[2] & 0xC0) != 0x80 ||
                (bytes[3] & 0xC0) != 0x80) return 0;
            if (*bytes == 0xF0 && bytes[1] < 0x90) return 0; // Overlong
            if (*bytes == 0xF4 && bytes[1] > 0x8F) return 0; // Above U+10FFFF
            if (*bytes > 0xF4) return 0; // Invalid
            bytes += 4;
        } else {
            return 0; // Invalid leading byte
        }
    }
    return 1;
}


void
spin(void) {
    static time_t last;
    time_t now;

    if (!isatty(2))
        return;

    time(&now);
    if (now != last) {
        fprintf(stderr, "[%lu]\r", n_objects);
        last = now;
    }
}


int
is_newer(const struct stat *a,
	 const struct stat *b) {
    if (a->st_mtim.tv_sec > b->st_mtim.tv_sec ||
	(a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
	 a->st_mtim.tv_nsec > b->st_mtim.tv_nsec))
	return 1;
    if (a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
	a->st_mtim.tv_nsec == b->st_mtim.tv_nsec)
	return 0;
    return -1;
}

int
walker(const char *path,
       const struct stat *sp,
       int flag,
       struct FTW *fp) {
    UChar utf16_input[8192];
    int32_t utf16_len;
    int rc_nfd, rc_nfc;


    ++n_objects;
    spin();

    if (flag == FTW_NS) {
        n_unread++;
        return 0;
    }

    if (is_ascii(path+fp->base)) {
	if (f_verbose > 1)
	    printf("%s: ASCII\n", path);
	
        n_ascii++;
        return 0;
    }

    if (!is_valid_utf8(path+fp->base)) {
        printf("%s: Unknown Encoding - Skipping\n", path);
        n_unknown++;
        return 0;
    }

    if (utf8_to_utf16(path+fp->base, utf16_input, &utf16_len) < 0)
        return -1;

    rc_nfd = is_nfd(utf16_input, utf16_len);
    if (rc_nfd < 0)
        return rc_nfd;

    rc_nfc = is_nfc(utf16_input, utf16_len);
    if (rc_nfc < 0)
        return rc_nfc;

    if (!rc_nfc && !rc_nfd) {
	if (f_verbose > 1)
	    printf("%s: UTF8\n", path);
	
        n_other++;
    }

    if (rc_nfc && !rc_nfd) {
	if (f_verbose > 1)
	    printf("%s: NFC\n", path);
	
        ++n_nfc;
    }

    if ((rc_nfd||1) && !rc_nfc) {
        char nfc_output[8192];
        int32_t nfc_len;
        struct stat nfc_sb;
        char nfd_timebuf[256];

        ++n_nfd;

        if (to_nfc(utf16_input, utf16_len, nfc_output, &nfc_len) < 0) {
            fprintf(stderr, "to_nfc: Error\n");
            return -1;
        }

        if (strcmp(nfc_output, path+fp->base) == 0) {
            fprintf(stderr, "%s: NFC Conversion to Identical String - Skipping\n",
                    path);
            return 0;
        }

        time2str(sp->st_mtime, nfd_timebuf, sizeof(nfd_timebuf));

        if (lstat(nfc_output, &nfc_sb) == 0) {
            char nfc_timebuf[256];

            time2str(nfc_sb.st_mtime, nfc_timebuf, sizeof(nfc_timebuf));

	    if (is_newer(&nfc_sb, sp) >= 0) {
                if (f_autofix) {
                    if (f_debug)
                        printf("%s: Collision - %s %s & Keep newer NFC (%s > %s) [size: %lu vs %lu]\n",
                               path,
			       f_remove ? "Remove" : "Rename",
                               rc_nfd ? "NFD" : "UTF8",
                               nfc_timebuf, nfd_timebuf,
                               nfc_sb.st_size, sp->st_size);

		    if (f_autofix > 1)
			add_action(dirname(path, NULL), sp, path+fp->base, &nfc_sb, nfc_output, ACT_REMOVE_NFD);
                } else {
                    if (f_verbose)
                        printf("%s: NFD\n", path);
                    else
                        puts(path);
                }
            } else {
                if (f_autofix) {
                    if (f_debug)
                        printf("%s: Collision - %s older NFC & Rename %s (%s < %s) [size: %lu vs %lu]\n",
                               path,
			       f_remove ? "Remove" : "Rename",
                               rc_nfd ? "NFD" : "UTF8",
                               nfc_timebuf, nfd_timebuf,
                               nfc_sb.st_size, sp->st_size);

		    if (f_autofix > 1)
			add_action(dirname(path, NULL), sp, path+fp->base, &nfc_sb, nfc_output, ACT_REMOVE_NFC);
                } else {
                    if (f_verbose)
                        printf("%s: NFD\n", path);
                    else
                        puts(path);
                }
            }
            n_coll++;

        } else {

            if (f_autofix) {
                if (f_debug)
                    printf("%s: Renaming %s to NFC (%s) [size: %lu]\n",
                           path,
                           rc_nfd ? "NFD" : "UTF8",
                           nfd_timebuf,
                           sp->st_size);

                add_action(dirname(path, NULL), sp, path+fp->base, NULL, nfc_output, ACT_RENAME_NFD);
            } else {
                if (f_verbose)
                    printf("%s: NFD\n", path);
                else
                    puts(path);
            }
        }
    }

    return 0;
}

char *
mkunique(const char *name,
	 const struct stat *sp) {
    char *buf;
    size_t buflen = strlen(name)+10;
    struct stat sb;
    unsigned int i = 0;

    
    buf = malloc(buflen);
    if (!buf)
	return NULL;
    
    do {
	if (S_ISDIR(sp->st_mode)) {
	    /* aaa -> aaa (0) */
	    snprintf(buf, buflen, "%s (%u)", name, i);
	} else {
	    char *cp = strrchr(name, '.');
	    if (!cp) {
		/* aaa -> aaa (0) */
		snprintf(buf, buflen, "%s (%u)", name, i);
	    } else {
		/* aaa.doc -> aaa (0).doc */
		
		int len = cp-name;
		snprintf(buf, buflen, "%.*s (%u)%s", len, name, i, name+len);
	    }
	}
	++i;
    } while (lstat(buf, &sb) == 0);

    return buf;
}


int
main(int argc,
     char *argv[]) {
    int i, j;
    ACTION *ap;
    char *cwd = NULL;

    argv0 = argv[0];

    setup();

    for (i = 1; i < argc && argv[i][0] == '-'; ++i)
        for (j = 1; argv[i][j]; j++)
            switch (argv[i][j]) {
	    case 'V':
		printf("[pnfdscan, version %s - %s]\n", PACKAGE_VERSION, PACKAGE_URL);
		exit(0);
            case 'v':
                f_verbose++;
                break;
            case 'a':
                f_autofix++;
                break;
            case 'n':
                f_update = 0;
                break;
            case 'i':
                f_ignore++;
                break;
	    case 'r':
		f_remove++;
		break;
            case 'd':
                f_debug++;
                break;
            case 'x':
                f_mount++;
                break;
            case 'h':
                printf("Usage:\n  %s [<options>*] <path-1> [.. <path-N>]\n", argv[0]);
                puts("\nOptions:");
                puts("  -h          Display this");
                puts("  -v          Increase verbosity");
		puts("  -V          Display version");
                puts("  -n          No-update (dry-run)");
                puts("  -d          Increase debug level");
                puts("  -i          Ignore non-fatal errors");
		puts("  -r          Remove (instead of rename) NFC objects");
                puts("  -a          Autofix mode (use -aa to remove collisions)");
                puts("  -x          Do not cross filesystem boundaries");
                exit(0);
            default:
                fprintf(stderr, "%s: Error: -%c: Invalid switch\n", argv[0], argv[i][j]);
                exit(1);
            }

    if (f_verbose > 2)
        puts("Scanning:");

    for (; i < argc; i++)
        nftw(argv[i], walker, 9999, FTW_PHYS|FTW_CHDIR|(f_mount ? FTW_MOUNT : 0));


    if (n_actions > 0 && f_verbose < 2)
        printf("Processing %lu objects:\n", n_actions);

    for (ap = actions; ap; ap = ap->next) {
        if (!cwd || strcmp(cwd, ap->dir) != 0) {
            if (chdir(ap->dir) < 0) {
                fprintf(stderr, "%s: Error: %s: chdir: %s\n",
                        argv0, ap->dir, strerror(errno));
                exit(1);
            }

            cwd = ap->dir;
        }

	switch (ap->type) {
	case ACT_RENAME_NFD:
	    /* No name collision -> just rename to NFC */
	    if (f_update) {
		if (rename(ap->nfd.name, ap->nfc.name) < 0) {
		    fprintf(stderr, "%s: Error: %s/%s -> %s: Rename: %s\n",
			    argv0, ap->dir, ap->nfd.name, ap->nfc.name, strerror(errno));
		    exit(1);
		} 
		printf("%s/%s -> %s: Renamed NFD\n",
		       ap->dir, ap->nfd.name, ap->nfc.name);
	    } else {
		printf("%s/%s -> %s: Renamed NFD (NOT)\n",
		       ap->dir, ap->nfd.name, ap->nfc.name);
	    }
	    break;
	    
	case ACT_REMOVE_NFD:
	    /* Collision, remove NFD and keep NFC */
	    
	    if (!f_remove) {
		/* Rename NFD to a unique name to avoid collisions */
		char *new = mkunique(ap->nfc.name, &ap->nfd.sb);

		if (f_update) {
		    if (rename(ap->nfd.name, new) < 0) {
			fprintf(stderr, "%s: Error: %s/%s -> %s: Rename NFD: %s\n",
				argv0, ap->dir, ap->nfd.name, new, strerror(errno));
			if (f_ignore)
			    continue;
			exit(1);
		    } 
		    printf("%s/%s -> %s: Renamed NFD & Kept NFC\n",
			   ap->dir, ap->nfd.name, new);
		} else {
		    printf("%s/%s -> %s: Renamed NFD & Kept NFC (NOT)\n",
			   ap->dir, ap->nfd.name, new);
		}
		free(new);
	    } else {
		int rc;
		
		if (f_update) {
		    if (S_ISDIR(ap->nfd.sb.st_mode)) 
			rc = rmdir(ap->nfd.name);
		    else
			rc = unlink(ap->nfd.name);
		    if (rc < 0) {
			fprintf(stderr, "%s: Error: %s/%s: Remove NFD: %s\n",
				argv0, ap->dir, ap->nfd.name, strerror(errno));
			if (f_ignore)
			    continue;
			exit(1);
		    }
		    printf("%s/%s: Removed NFD & Kept NFC\n",
			   ap->dir, ap->nfd.name);
		} else {
		    printf("%s/%s: Removed NFD & Kept NFC (NOT)\n",
			   ap->dir, ap->nfd.name);
		}
	    }
	    break;
	    
	case ACT_REMOVE_NFC:
	    /* Collision, remove NFC and rename NFD to NFC */
	    
	    if (!f_remove) {
		/* Rename NFC to a unique name to avoid collisions */
		char *new = mkunique(ap->nfc.name, &ap->nfc.sb);

		if (f_update) {
		    if (rename(ap->nfc.name, new) < 0) {
			fprintf(stderr, "%s: Error: %s/%s -> %s: Rename NFC: %s\n",
				argv0, ap->dir, ap->nfc.name, new, strerror(errno));
			if (f_ignore)
			    continue;
			exit(1);
		    } 
		    printf("%s/%s -> %s: Renamed NFC\n",
			   ap->dir, ap->nfc.name, new);
		} else {
		    printf("%s/%s -> %s: Renamed NFC (NOT)\n",
			   ap->dir, ap->nfc.name, new);
		}
		free(new);
	    }
	    
	    if (f_update) {
		if (rename(ap->nfd.name, ap->nfc.name) < 0) {
		    fprintf(stderr, "%s: Error: %s/%s -> %s: Rename NFD: %s\n",
			    argv0, ap->dir, ap->nfd.name, ap->nfc.name, strerror(errno));
		    exit(1);
		} 
		printf("%s/%s -> %s: %sRenamed NFD\n",
		       ap->dir, ap->nfd.name, ap->nfc.name,
		       f_remove ? "Removed NFC & " : "");
	    } else {
		printf("%s/%s -> %s: %sRenamed NFD (NOT)\n",
		       ap->dir, ap->nfd.name, ap->nfc.name,
		       f_remove ? "Removed NFC & " : "");
	    }
	    break;
	}
    }

    printf("[%lu ascii, %lu nfc, %lu nfd, %lu other, %lu unknown & %lu collisions; %lu objects, %lu unreadable, %lu renamed & %lu removed]\n",
           n_ascii, n_nfc, n_nfd, n_other, n_unknown, n_coll,
           n_objects, n_unread, n_renamed, n_removed);

    return 0;
}
