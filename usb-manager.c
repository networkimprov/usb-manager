#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>

#define BUF_SZ		100

/*
 * Sets things based on sysfs vbus state as otherwise running
 * ttyGS0 will keep the system busy.
 */

static int poll_vbus(const char *filename, int *status_changed, int *connected)
{
	int ret, fd;
	ssize_t len;
	char buf[BUF_SZ] = "";
	struct pollfd fds;
	int timeout_msecs = 20000;

	*status_changed = 0;
	*connected = 0;

	fd = open(filename, O_RDONLY);
	if (fd < 1)
		return fd;

	len = read(fd, buf, BUF_SZ);
	if (len < 1)
		goto out;

	fds.fd = fd;
	fds.events = POLLPRI;
	fds.revents = 0;

	if (lseek(fd, 0, SEEK_SET) < 0) {
		perror("lseek");
		goto out;
	}

	ret = poll(&fds, 1, timeout_msecs);
	if (ret == 1)
		*status_changed = 1;

	len = read(fd, buf, BUF_SZ);
	if (len < 1)
		goto out;

	if (!strncmp(buf, "on", 2))
		*connected = 1;

out:
	return close(fd);
}

static int configure_usb_console(int connected)
{
	char *args[8];
	int res, pid;

	args[0] = "/usr/bin/systemctl";
	args[1] = connected ? "start" : "stop";
	args[2] = "getty@ttyGS0.service";
	args[3] = NULL;

	pid = fork();
	if (pid < 0) {
		printf("ERROR: Could not fork\n");
	} else if (pid == 0) {
		res = execvp(args[0], args);
		if (res) {
			printf("ERROR: systemctl failed with %i\n", res);
			return res;
		}
		exit(0);
	} else {
		/* Parent */
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret, status_changed, connected;

	if (argc != 2) {
		printf("Usage: %s <sysfs path>\n", argv[0]);
		return 1;
	}

	/* Check initial state */
	ret = poll_vbus(argv[1], &status_changed, &connected);
	if (ret)
		return ret;
	ret = configure_usb_console(connected);

	/* Keep checking when state changes */
	while (1) {
		ret = poll_vbus(argv[1], &status_changed, &connected);
		if (ret)
			return ret;
		printf("status_changed: %i connected: %i\n", status_changed, connected);
		if (status_changed)
			ret = configure_usb_console(connected);
		if (ret)
			return ret;
		if (ret != 0) {
			printf("Polling failed with %i\n", ret);
			break;
		}
	}

	return ret;
}
