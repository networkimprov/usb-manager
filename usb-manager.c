#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define BUF_SZ		100

#define F_IINLIM_PC	(1 << 5)
#define F_VBUS_STAT_PC	(1 << 4)
#define CHARGING	(1 << 3)
#define B_PERIPHERAL	(1 << 2)
#define B_IDLE		(1 << 1)
#define VBUS		(1 << 0)

struct files {
	char *desc;
	char *file;
	char *match;
	unsigned int mask;
	struct pollfd *pfd;
};

static struct files sysfs[] = {
	{ .desc = "twl_vbus",
	  .file = "/sys/bus/platform/devices/48070000.i2c:twl@48:twl4030-usb/vbus",
	  .match = "on", .mask = VBUS, },
	{ .desc = "musb_vbus",
	  .file = "/sys/bus/platform/devices/musb-hdrc.0.auto/vbus", },
	{ .desc = "musb_mode",
	  .file = "/sys/bus/platform/devices/musb-hdrc.0.auto/mode",
	  .match = "b_idle", .mask = B_IDLE, },
	{ .desc = "bq_status",
	  .file = "/sys/class/power_supply/bq24190-battery/status",
	  .match = "Charging", .mask = CHARGING, },
	{ /* Sentinel */ },
};

/*
 * Sets things based on sysfs vbus state as otherwise running
 * ttyGS0 will keep the system busy.
 */
static int parse_sysfs(struct files *f, char *val, unsigned int *status)
{
	if (!f->match)
		return 0;

	if (!strcmp(f->match, val))
		*status |= f->mask;
	else
		*status &= ~f->mask;

	/* MUSB provides multiple values.. */
	if (f->mask == B_IDLE) {
		if (!strcmp("b_peripheral", val))
			*status |= B_PERIPHERAL;
		else
			*status &= ~B_PERIPHERAL;
	}

	return 0;
}

static int poll_vbus(struct files *sysfs, int timeout_msecs, sigset_t mask,
		int *status_changed, unsigned int *status)
{
	int ret;
	ssize_t len;
	char buf[BUF_SZ];
	struct pollfd fds[8];
	struct files *f = sysfs;
	sigset_t orig_mask;
	unsigned int old_status = *status;
	int i = 0;

	*status_changed = 0;
	*status = 0;

	ret = sigprocmask(SIG_BLOCK, &mask, &orig_mask);
	if (ret < 0)
		return ret;

	while (f->file != NULL) {
		int fd;

		fd = open(f->file, O_RDONLY);
		if (fd < 1)
			continue;

		len = read(fd, buf, BUF_SZ);
		if (len < 1) {
			close(fd);
			continue;
		}

		fds[i].fd = fd;
		fds[i].events = POLLPRI;
		fds[i].revents = 0;
		f->pfd = &fds[i];

		if (lseek(fd, 0, SEEK_SET) < 0) {
			perror("lseek");
			goto out;
		}
		f++;
		i++;
	}
	f = sysfs;

	ret = poll(fds, i, timeout_msecs);
	if (ret < 0)
		goto out;

	while (f->file != NULL) {
		if (!f->pfd->fd)
			continue;

		memset(buf, 0, BUF_SZ);

		len = read(f->pfd->fd, buf, BUF_SZ);
		if (len < 1)
			continue;

		if (len > 1)
			buf[len - 1] = 0;

		parse_sysfs(f, buf, status);
		f++;
	}
	f = sysfs;

out:
	while (f->file != NULL && f->pfd) {
		if (!f->pfd)
			continue;

		if (f->pfd->fd)
			close(f->pfd->fd);
		f->pfd = NULL;
		f++;
	}

	if (old_status != *status)
		*status_changed = 1;

	printf("status: 0x%08x status changed: %i\n", *status, *status_changed);

	ret = sigprocmask(SIG_SETMASK, &orig_mask, NULL);

	return 0;
}

static int configure_charger_led(int value)
{
	char buf[256];
	int res;

	sprintf(buf,
		"/usr/bin/echo %i > /sys/class/leds/pca963x:blue/brightness",
		value);
	res = system(buf);

	return res;
}

static int configure_charger(int connected, int pc)
{
	if (connected) {
		int fd, f_iinlim;
		ssize_t len;
		char buf[BUF_SZ];

		fd = open("/sys/class/power_supply/bq24190-charger/f_iinlim",
			  O_RDONLY);
		if (fd < 1 )
			return fd;

		len = read(fd, buf, BUF_SZ);
		if (len < 1) {
			close(fd);
			return len;
		}

		if (len > 1)
			buf[len - 1] = 0;

		f_iinlim = atoi(buf);

		configure_charger_led(1 + (32 * f_iinlim));
	} else {
		configure_charger_led(0);
	}

	return 0;
}

/*
 * Depends on /etc/systemd/system/anvl-getty-usb@.service
 * having something like this:
 * [Unit]
 * Description=Serial Getty on %I
 *
 * IgnoreOnIsolate=yes
 *
 * [Service]
 * ExecStart=-/sbin/agetty 115200 %I $TERM
 * Type=idle
 * Restart=always
 * UtmpIdentifier=%I
 * TTYPath=/dev/%I
 * TTYReset=yes
 * TTYVHangup=yes
 * KillMode=process
 * IgnoreSIGPIPE=no
 * SendSIGHUP=yes
 *
 * [Install]
 * WantedBy=getty.target
 */
static int configure_usb_console(int connected)
{
	struct stat buf;
	char *args[8];
	int res, pid;

	args[0] = "/usr/bin/systemctl";
	args[1] = connected ? "start" : "stop";
	args[2] = "anvl-getty-usb@ttyGS0.service";
	args[3] = NULL;

	res = stat(args[0], &buf);
	if (res) {
		fprintf(stderr, "ERROR: Could not find %s\n", args[0]);
		return res;
	}

	signal(SIGCHLD, SIG_DFL);
	pid = fork();
	if (pid < 0) {
		printf("ERROR: Could not fork\n");
	} else if (pid == 0) {
		res = execvp(args[0], args);
		if (res)
			printf("ERROR: systemctl failed with %i\n", errno);
		exit(res);
	} else {
		/* Parent */
		wait(&res);
	}

	return 0;
}

void signal_handler(int signal)
{
	configure_charger(0, 0);
	configure_usb_console(0);
	exit(0);
}

int main(int argc, char **argv)
{
	int ret, status_changed;
	sigset_t mask;
	struct sigaction act;
	unsigned int status;

	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;

	ret = sigaction(SIGINT, &act, 0);
	if (ret)
		return ret;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);

	/* Check initial state */
	ret = poll_vbus(sysfs, 1, mask, &status_changed, &status);
	if (ret)
		return ret;

	ret = configure_charger(status & CHARGING, status & B_PERIPHERAL);
	if (ret)
		return ret;

	if (status & B_PERIPHERAL) {
		ret = configure_usb_console(1);
		if (ret)
			return ret;
	}

	/* Keep checking when state changes */
	while (1) {
		ret = poll_vbus(sysfs, 5000, mask, &status_changed, &status);
		if (ret)
			return ret;

		while (status_changed)  {
			int previous = status;

			ret = configure_charger(status & CHARGING, status & B_PERIPHERAL);
			if (ret)
				return ret;

			ret = configure_usb_console(status & B_PERIPHERAL);
			if (ret)
				return ret;

			/* Did status change? */
			ret = poll_vbus(sysfs, 1, mask, &status_changed, &status);
			if (ret)
				return ret;

			if (previous != status)
				status_changed = 1;
		}

		if (ret != 0) {
			printf("Polling failed with %i\n", ret);
			break;
		}
	}

	return ret;
}
