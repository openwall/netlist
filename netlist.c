/*
 * 18 nov 1999  netlist for linux by stran9er
 * 19 nov 1999  hacked for strict /proc with ip hidding by freelsd
 *  5 nov 2001  udp/raw support by stran9er
 *  6 nov 2001  various relatively unimportant modifications by solar
 *  6 nov 2001  speed up by stran9er
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <pwd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

static int connsize = 0;
static int commcols = 0;
static int commlen = 7;

static void fatal(const char *, ...)
  __attribute__ ((noreturn))
  __attribute__ ((format (printf, 1, 2)));

struct netinfo {
  struct netinfo *next;
  unsigned long locip;
  unsigned short locport;
  unsigned long remip;
  unsigned short remport;
  int state;
  int uid;
  unsigned long inode;
  int pid;
  int fd;
  int type; /* tcp, udp, raw */
  char comm[16];
};

static struct netinfo *ni = NULL;
static struct netinfo **bi_idx = NULL;

static void fatal(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  exit(1);
}

static int netinfo_cmp(const void *l, const void *r) {
  return (*(struct netinfo **)l)->inode - (*(struct netinfo **)r)->inode;
}

static struct netinfo *read_tcp_table(void) {
  char *fnames[] = {
    "/proc/net/raw",
    "/proc/net/udp",
    "/proc/net/tcp"
  };
  FILE *f;
  struct netinfo *tmp;
  uid_t uid = getuid();
  int fno, i;
  struct stat st;
  gid_t glist[NGROUPS_MAX];
  int size, proc;

  if ( stat("/proc/net", &st) != 0 )
    fatal("stat: /proc/net: %s\n", strerror(errno));

  if ( (size = getgroups(NGROUPS_MAX, glist)) == -1 )
    fatal("getgroups: %s\n", strerror(errno));

  proc = st.st_gid == getgid();
  while (size--)
    proc |= st.st_gid == glist[size];

  for (fno = 0; fno < (sizeof(fnames) / sizeof(char *)); fno++) {
    if (!(f = fopen(fnames[fno], "r")))
      fatal("fopen: %s: %s\n", fnames[fno], strerror(errno));

    while (!feof(f)) {
      int n;

      if ( !(tmp = (struct netinfo *)calloc(1, sizeof(struct netinfo))) )
	fatal("calloc: %s\n", strerror(ENOMEM));

      n = fscanf(f,
	"%*[^\n]\n%*d: %lx:%hx %lx:%hx %x %*x:%*x %*x:%*x %*x %d %*d %ld",
	&tmp->locip, &tmp->locport,
	&tmp->remip, &tmp->remport,
	&tmp->state, &tmp->uid, &tmp->inode);

      if (n == 7 && tmp->inode && (tmp->uid == uid || !uid || proc)) {
	if (tmp->inode)
	  connsize++;
	tmp->type = fno;
	tmp->next = ni;
	ni = tmp;
      } else
	free(tmp);
      if (n != 7) break;
    } /* for each line */

    fclose(f);
  } /* for each file */

  /* build sorted table of inodes */
  if ( !(bi_idx = malloc(connsize * sizeof(struct netinfo *))) )
    fatal("malloc: %s\n", strerror(ENOMEM));
    
  for (i = 0, tmp = ni; tmp; tmp = tmp->next)
    if (tmp->inode)
      bi_idx[i++] = tmp;

  qsort(bi_idx, connsize, sizeof(struct netlist *), netinfo_cmp);
  
  return ni;
}

static void scan_proc_table(void) {
  DIR *d_proc, *d_fd;
  struct dirent *proc_ent, *fd_ent;

  if (!(d_proc = opendir("/proc")))
    fatal("opendir: /proc: %s\n", strerror(errno));

  while ((proc_ent = readdir(d_proc))) {
    char fd_path[PATH_MAX];
    int pid;

    if (!isdigit((int)(unsigned char)proc_ent->d_name[0]))
      continue;

    pid = atoi(proc_ent->d_name);
    snprintf(fd_path, PATH_MAX, "/proc/%d/fd", pid);

    if (!(d_fd = opendir(fd_path)))
      continue;

    while ((fd_ent = readdir(d_fd))) {
      char file_path[PATH_MAX];
      struct stat st;
      struct netinfo key, *mat = &key, **xmat;

      if (!isdigit((int)(unsigned char)fd_ent->d_name[0]))
	continue;

      snprintf(file_path, PATH_MAX, "%s/%s", fd_path, fd_ent->d_name);

      if ( stat(file_path, &st) == -1 ||
	   st.st_dev )
	continue;

      key.inode = st.st_ino;
      xmat = bsearch(&mat, bi_idx, connsize, sizeof(struct netinfo *),
		      netinfo_cmp);
      if (xmat) {
	mat = *xmat;
	if (mat->pid) {
	  struct netinfo *tmp;

	  if ( !(tmp = (struct netinfo *)malloc(sizeof(struct netinfo))) )
	    fatal("malloc: %s\n", strerror(ENOMEM));
	  memcpy(tmp, mat, sizeof(struct netinfo));
	  mat->next = tmp;
	  mat = tmp;
	}
	mat->pid = pid;
	mat->fd = atoi(fd_ent->d_name);
      }
    } /* while readdir */

    closedir(d_fd);
  } /* while readdir */

  closedir(d_proc);
}

static void read_proc_stat(void) {
  struct netinfo *np;
  FILE *f;

  for (np = ni; np; np = np->next)
    if (np->pid) {
      char stat_path[PATH_MAX];
      char *p;

      snprintf(stat_path, PATH_MAX, "/proc/%d/stat", np->pid);
      if (!(f = fopen(stat_path, "r"))) continue;
      fscanf(f, "%*d (%15[^)])", np->comm);
      fclose(f);

      for (p = np->comm; *p; p++)
	if (!isprint((int)(unsigned char)*p))
	  *p = '?';

      if ((p - np->comm) > commlen)
	commlen = p - np->comm;
    }
}

static char *state[] = {
  "??", "ESTAB", "SYNSNT", "SYNRCV", "FINW1", "FINW2", "TIMEW", "CLOSE",
  "CLOSEW", "LASTACK", "LISTEN", "CLOSING"
};

static void output_netlist(void) {
  struct netinfo *np;
  struct passwd *pw;

  for (np = ni; np; np = np->next)
    if (np->inode) {
      char uid[32];

      if (!(pw = getpwuid(np->uid)))
        snprintf(uid, sizeof(uid), "%d", np->uid);

      printf("%-8s %-5d %-*.*s%c%2d ",
	pw ? pw->pw_name : uid, np->pid, commcols, commcols, np->comm,
	strlen(np->comm) > commcols ? '+' : ' ', np->fd);
      switch (np->type) {
	case 2: printf("tcp "); break;
	case 1: printf("udp "); break;
	case 0: printf("raw ");
      }
      printf("%15s:%-5d ",
	inet_ntoa(*(struct in_addr *)&np->locip), np->locport);
      printf("%15s:%-5d ",
	inet_ntoa(*(struct in_addr *)&np->remip), np->remport);
      printf("%s\n",
	(np->state > (sizeof(state) / sizeof(char *))) ?
	"??" : state[np->state]);
    }
}

int main(void) {
  struct winsize ws;
  
  if (!read_tcp_table())
    fatal("No active Internet connections found\n");

  if (setgid(getgid())) /* drop egid for restricted /proc */
    fatal("setgid: %s\n", strerror(errno));

  if (setuid(getuid()))
    fatal("setuid: %s\n", strerror(errno));

  scan_proc_table();

  read_proc_stat();

  commcols = 7;
  if (ioctl(1, TIOCGWINSZ, &ws) != -1) {
    commcols = ws.ws_col - 73;
    if (commcols < 7)
      commcols = 7;
    if (commcols > commlen)
      commcols = commlen;
  }

  printf("USER     PID   %-*s FD TYPE       LOCAL IP:PORT "
    "       REMOTE IP:PORT  STATE\n", commcols, "COMMAND");
  output_netlist();

  return 0;
}
