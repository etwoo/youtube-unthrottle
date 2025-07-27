#include "test_network.h"

#include "sandbox/verify.h" /* for SANDBOX_VERIFY_STATIC_IP_ADDRESS */

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h> /* for close() */

enum greatest_test_res
check_network(bool allowed)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_LTE(0, sfd);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, SANDBOX_VERIFY_STATIC_IP_ADDRESS, &sa.sin_addr);

	const int connected = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	const int connected_errno = errno;
	const int closed = close(sfd);
	if (allowed) {
		ASSERT_EQ(0, connected);
	} else {
		ASSERT_EQ(-1, connected);
#if defined(__APPLE__)
		ASSERT_EQ(EPERM, connected_errno);
#else
		ASSERT_EQ(EACCES, connected_errno);
#endif
	}
	ASSERT_EQ(0, closed);

	PASS();
}
