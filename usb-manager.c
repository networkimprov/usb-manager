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
#include <usbg/usbg.h>

#define BUF_SZ		1024

#define F_IINLIM_PC	(1 << 5)
#define F_VBUS_STAT_PC	(1 << 4)
#define CHARGING	(1 << 3)
#define B_PERIPHERAL	(1 << 2)
#define B_IDLE		(1 << 1)
#define VBUS		(1 << 0)

#define B_IDLE_VBUS(s)	((s) == (B_IDLE | VBUS))

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

static int debug;

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
		if (!strcmp("(null)", val))
			*status |= B_IDLE;
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

	if (debug)
		printf("Poll sysfs_notify events status: 0x%08x status changed: %i\n",
		       *status, *status_changed);

	ret = sigprocmask(SIG_SETMASK, &orig_mask, NULL);

	return 0;
}

static int read_sysfs_entry(const char *file, char *buf)
{
	ssize_t len;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 1 )
		return fd;
	len = read(fd, buf, BUF_SZ);
	close(fd);
	if (len < 1)
		return 0;
	if (len > 1) {
		len--;
		buf[len] = 0;
	}

	return len;
}

static int write_sysfs_entry(const char *file, const char *val, size_t count)
{
	ssize_t len;
	int fd;

	fd = open(file, O_RDWR);
	if (fd < 1 )
		return fd;
	len = write(fd, val, count);
	if (len < count)
		return -EINVAL;
	close(fd);

	return len;
}


static int configure_charger_led(int value)
{
	char val[32];
	ssize_t len;
	const char *name =
		"/sys/class/leds/pca963x:blue/brightness";
	sprintf(val, "%i\n", value);
	len = write_sysfs_entry(name, val, strlen(val)); 
	if (len < 0)
		return len;

	return 0;
}

#define MAX_CURRENT	8

/* Charger current in mA */
static const unsigned int charger_current[MAX_CURRENT] = {
	100,
	150,
	500,
	900,
	1200,
	1500,
	2000,
	3000,
};

/* Charger type detected by bq24190 */
enum charger_type {
	CHARGER_UNKNOWN = 0,
	CHARGER_USBHOST,
	CHARGER_ADAPTER,
	CHARGER_OTG,
};

static int force_charger_current(int val, const char *desc)
{
	const char *file_f_iinlim =
		"/sys/class/power_supply/bq24190-charger/f_iinlim";
	char buf[8];
	int res;

	if (val > 7)
		val = 7;

	sprintf(buf, "%i\n", val);
	if (desc)
		fprintf(stderr, "WARNING: Forcing charger current, %s\n",
			desc);
	res = write_sysfs_entry(file_f_iinlim, buf, 2);
	if (res < 0)
		return -EINVAL;

	return 0;
}

static int dumb_charger_retries;

static int configure_charger(unsigned int status)
{
	int res, b_idle, enumerated, charging;

	if (!status)
		goto out;

	b_idle = (status & (B_IDLE | VBUS)) == ((B_IDLE | VBUS));
	enumerated = ((status & (B_PERIPHERAL | VBUS)) == (B_PERIPHERAL | VBUS));
	charging = (status & CHARGING);

	if (b_idle || enumerated || charging) {
		const char *file_f_iinlim =
			"/sys/class/power_supply/bq24190-charger/f_iinlim";
		const char *file_f_vbus_stat =
			"/sys/class/power_supply/bq24190-charger/f_vbus_stat";
		const char *file_battery_stat =
			"/sys/class/power_supply/bq24190-battery/status";

		int f_iinlim, f_vbus_stat;
		unsigned int current;
		char buf[BUF_SZ];
		char *charger_desc;

		res = read_sysfs_entry(file_f_iinlim, buf);
		if (res < 1)
			return -EINVAL;
		f_iinlim = atoi(buf);
		if (f_iinlim >= MAX_CURRENT)
			f_iinlim = 0;

		res = read_sysfs_entry(file_f_vbus_stat, buf);
		if (res < 1)
			return -EINVAL;
		f_vbus_stat = atoi(buf);

		switch (f_vbus_stat) {
		case CHARGER_UNKNOWN:
			charger_desc = "unkown";
			dumb_charger_retries++;

			/* Workaround for dumb charger with d+ and d- shorted */
			if ((dumb_charger_retries > 2) && b_idle && (f_iinlim) == 0) {
				res = force_charger_current(5,
					"1500mA, dumb charger?");
				if (res < 0)
					return -EINVAL;
				f_iinlim = 5;
			}
			break;
		case CHARGER_USBHOST:
			charger_desc = "USB host";
			dumb_charger_retries = 0;

			/* Workaround for bq24190 OTG pin being high */
			if (b_idle && (f_iinlim > 0)) {
				res = force_charger_current(0,
					"100mA, OTG pin high?");
				if (res < 0)
					return -EINVAL;
				f_iinlim = 0;
			} else if (enumerated && (f_iinlim == 0)) {
				res = force_charger_current(2,
					"500mA, configured while charging?");
				if (res < 0)
					return -EINVAL;
				f_iinlim = 2;
			}
			break;
		case CHARGER_ADAPTER:
			charger_desc = "adapter port";
			dumb_charger_retries = 0;
			break;
		case CHARGER_OTG:
			charger_desc = "OTG";
			dumb_charger_retries = 0;
			break;
		default:
			dumb_charger_retries = 0;
			break;
		}

		res = read_sysfs_entry(file_battery_stat, buf);
		if (res < 1)
			return -EINVAL;

		current = charger_current[f_iinlim];

		if (debug)
			printf("%s %s %s charger %umA iinlim: %i vbus: %i\n",
			       buf, enumerated ? "enumerated" : "b_idle",
			       charger_desc, current, f_iinlim, f_vbus_stat);

		if (!strcmp("Full", buf))
			configure_charger_led(0);
		else
			configure_charger_led(1 + (32 * f_iinlim));

		return 0;
	}

out:
	dumb_charger_retries = 0;
	configure_charger_led(0);
	res = force_charger_current(0, NULL);
	if (res < 0)
		return -EINVAL;

	return 0;
}

#define UDC		"musb-hdrc.0.auto"
#define UDC_SZ		32
#define VENDOR		0x1d6b
#define PRODUCT		0x0106

/*
 * Based on the libusbg example at:
 * https://github.com/libusbg/libusbg/blob/master/examples/gadget-acm-ecm.c
 */
static int configure_usb_gadget(int connected)
{
	usbg_state *s;
	usbg_gadget *g;
	usbg_config *c;
	usbg_function *f_acm0, *f_ecm;
	int ret;

	/* We need minimum 700ms sleep for bq24190 charger detection */
	sleep(1);

	usbg_gadget_attrs g_attrs = {
			0x0200,			/* bcdUSB */
			0x00,			/* Defined at interface level */
			0x00,			/* subclass */
			0x00,			/* device protocol */
			0x0040,			/* Max allowed packet size */
			VENDOR,
			PRODUCT,
			0x0001,			/* Verson of device */
	};

	usbg_gadget_strs g_strs = {
			"0123456789",		/* Serial number */
			"NetworkImprov",	/* Manufacturer */
			"Anvl"			/* Product string */
	};

	usbg_config_strs c_strs = {
			"CDC ACM+ECM"
	};

	ret = usbg_init("/sys/kernel/config", &s);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: init %s :%s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		return -EINVAL;
	}

	g = usbg_get_first_gadget(s);
	if (!g && !connected)
		goto out;

	if (g) {
		if (connected) {
			char buf[UDC_SZ];
			ssize_t len;

			len = usbg_get_gadget_udc_len(g);
			if (len < 0)
				goto out;
			ret = usbg_get_gadget_udc(g, buf, len);
			if (ret < 0)
				goto out;
			if (!strcmp(UDC, buf))
				goto out;
			if (debug)
				printf("Enabling USB gadget\n");
			ret = usbg_enable_gadget(g, "musb-hdrc.0.auto");
			if (ret)
				goto out;
		} else {
			if (debug)
				printf("Disabling USB gadget\n");
			ret = usbg_disable_gadget(g);
			if (ret)
				goto out;
		}
		goto out;
	}

	ret = usbg_create_gadget(s, "g1", &g_attrs, &g_strs, &g);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: create %s: %s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		goto out;
	}

	ret = usbg_create_function(g, F_ACM, "usb0", NULL, &f_acm0);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: F_ACM %s: %s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		goto out;
	}

	ret = usbg_create_function(g, F_ECM, "usb0", NULL, &f_ecm);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: F_ECM %s: %s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		goto out;
	}

	/* NULL can be passed to use kernel defaults */
	ret = usbg_create_config(g, 1, "Anvl", NULL, &c_strs, &c);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: config %s: %s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		goto out;
	}

	ret = usbg_add_config_function(c, "acm.GS0", f_acm0);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: acm.GS0 %s: %s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		goto out;
	}

	ret = usbg_add_config_function(c, "ecm.usb0", f_ecm);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: ecm.usb0 %s: %s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		goto out;
	}

	ret = usbg_enable_gadget(g, DEFAULT_UDC);
	if (ret != USBG_SUCCESS) {
		fprintf(stderr, "ERROR: enable %s: %s\n", usbg_error_name(ret),
				usbg_strerror(ret));
		goto out;
	}

out:
	usbg_cleanup(s);

	return ret;
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
	configure_charger(0);
	configure_usb_console(0);
	configure_usb_gadget(0);
	exit(0);
}

#define TIMEOUT_DEFAULT_MS	20000

int main(int argc, char **argv)
{
	int ret, status_changed, recheck = 0, timeout_ms = 1;
	sigset_t mask;
	struct sigaction act;
	unsigned int status;

	if (argc > 1) {
		if (!strcmp(argv[1], "--help")) {
			printf("Usage: %s [--help|--debug]\n", argv[0]);
			return 0;
		}
		if (!strcmp(argv[1], "--debug")) {
			debug = 1;
		} else {
			fprintf(stderr, "ERROR: Invalid argument %s\n", argv[1]);
			return -EINVAL;
		}
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;

	ret = sigaction(SIGINT, &act, 0);
	if (ret)
		return ret;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);

	/* Keep checking when state changes */
	while (1) {
		ret = poll_vbus(sysfs, timeout_ms, mask, &status_changed, &status);
		if (ret)
			return ret;

		if (status_changed || recheck)  {
			ret = configure_charger(status);
			if (ret)
				return ret;
		}

		if (status_changed) {
			ret = configure_usb_gadget(status & VBUS);
			/* Ignore errors in case it was manually configured */
		}

		if (status_changed) {
			ret = configure_usb_console(status & B_PERIPHERAL);
			if (ret)
				return ret;
		}

		if (ret != 0) {
			printf("Polling failed with %i\n", ret);
			break;
		}

		if (status & CHARGING) {
			timeout_ms = 5000;
			recheck = 1;
		} else if (B_IDLE_VBUS(status) || (status & B_PERIPHERAL)) {
			timeout_ms = 1000;
			recheck = 1;
		} else {
			timeout_ms = TIMEOUT_DEFAULT_MS;
			recheck = 0;
		}
	}

	return ret;
}
