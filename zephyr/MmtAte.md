# Zepher Project Vulnerability Report

## Timeline

- 2022.5.7		  Report to vendor
- 2022.5.19        patch release
- 2022.8.31        CVE-2022-1841 assigned (CVSS3.x 7.2 HIGH)



> The [Zephyr Project](https://www.zephyrproject.org/) is a Linux Foundation hosted Collaboration Project. It’s an open source collaborative effort uniting developers and users in building a best-in-class small, scalable, real-time operating system (RTOS) optimized for resource-constrained devices, across multiple architectures.



## Product information

The following are based on commit `0f64fdfbfd41f5b5310f37f169a07b41cf9187c7` (May 7, 2022).

Patched in `182daf071f2d47c954bebfbab34eff3a340c7061`.

## Out-of-Bound Write in `tcp_flags`

### **Description**

In `subsys/net/ip/tcp.c`, function `tcp_flags`, when the incoming parameter `flags` is `ECN` or `CWR` , the `buf` will out-of-bounds write a byte zero.

### Details

When a malformed tcp packet is received, the `tcp_flags` function does not check the validity of the parameters, but directly parses the `th_flags` field in TCP header. When `th_flags` is `ECN` or `CWR`, in the tcp_flags function, `len` is always 0, and `buf[0-1]` will be written `'\\0'` . This will modify other data on the stack.

```c
static const char *tcp_flags(uint8_t flags)
{
#define BUF_SIZE 25 /* 6 * 4 + 1 */
	static char buf[BUF_SIZE];
	int len = 0;

	buf[0] = '\0';

	if (flags) {
		if (flags & SYN) {
			len += snprintk(buf + len, BUF_SIZE - len, "SYN,");
		}
		if (flags & FIN) {
			len += snprintk(buf + len, BUF_SIZE - len, "FIN,");
		}
		if (flags & ACK) {
			len += snprintk(buf + len, BUF_SIZE - len, "ACK,");
		}
		if (flags & PSH) {
			len += snprintk(buf + len, BUF_SIZE - len, "PSH,");
		}
		if (flags & RST) {
			len += snprintk(buf + len, BUF_SIZE - len, "RST,");
		}
		if (flags & URG) {
			len += snprintk(buf + len, BUF_SIZE - len, "URG,");
		}

		buf[len - 1] = '\0'; /* delete the last comma */
	}
#undef BUF_SIZE
	return buf;
}
```

```c
enum th_flags {
	FIN = BIT(0),
	SYN = BIT(1),
	RST = BIT(2),
	PSH = BIT(3),
	ACK = BIT(4),
	URG = BIT(5),
	ECN = BIT(6),
	CWR = BIT(7),
};
```

## References

https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-5c3j-p8cr-2pgh