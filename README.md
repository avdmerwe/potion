# potion

A console IP flow monitor. It listens on a network interface with
libpcap, aggregates what it sees into flows, and shows the busiest of
them with their average throughput: as many as fit on the screen,
refreshed once a second, sorted by rate.

```
+----------------------+----------------------+------------+----------+
| Source               | Destination          | Protocol   | Avg Rate |
+----------------------+----------------------+------------+----------+
| 10.0.0.14:44321      | 151.101.1.140:443    |    tcp     |     4.7m |
| 10.0.0.14:2049       | 10.0.0.22:757        | udp [frag] |    61.2k |
| 10.0.0.14:51314      | 8.8.8.8:53           |    udp     |    912.0 |
| 10.0.0.9             | 224.0.0.251          |    icmp    |    128.0 |
+----------------------+----------------------+------------+----------+
  potion 0.1.1 - 4 flows - press h for help               14:22:07
```

A flow is identified by the IP protocol, the type of service field, the
source and destination addresses, and the source and destination ports.
Only IPv4 is decoded. Fragmented datagrams are reassembled into the flow
they belong to once the fragment carrying the port numbers has been seen.

## Building

Build dependencies: a C compiler, `pkg-config`, and the development
files for libevent, libpcap and ncurses. On Debian or Ubuntu:

```sh
sudo apt install build-essential pkg-config libevent-dev libpcap-dev libncurses-dev
```

Then:

```sh
make
make check          # runs the test suite
sudo make install   # installs to /usr/local by default
```

`CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `prefix` and `DESTDIR` are all
honoured from the environment or the command line.

## Debian package

```sh
sudo apt install devscripts debhelper
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../potion_*.deb
```

## Usage

```
potion [options] <interface> [expression]
```

`expression` is a pcap filter, the same syntax `tcpdump` uses. Since
potion drops everything that is not IPv4, passing at least `ip` is
worthwhile.

```sh
sudo potion any
sudo potion eth0 ip and not port 22
sudo potion -f 512 -i 60 eth0
```

| Option | Meaning |
| --- | --- |
| `-s`, `--snaplen=<bytes>` | bytes captured per packet, 68 to 262144, or 0 for whole packets (default 128) |
| `-f`, `--flows=<n>` | maximum flows tracked, 16 to 1048576 (default 64) |
| `-a`, `--active=<minutes>` | active flow lifetime, 1 to 60 (default 30) |
| `-i`, `--inactive=<seconds>` | idle flow lifetime, 10 to 600 (default 30) |
| `-S`, `--syslog=<facility>` | syslog facility (default `user`) |
| `-P`, `--no-promisc` | leave the interface out of promiscuous mode |
| `-V`, `--version` | print the version |
| `-h`, `--help` | print the options |

Press `h` for help, `^L` to redraw, `q` to quit. The display needs a
terminal of at least 72 by 10 characters.

Capturing needs privileges, so potion is normally started through
`sudo`. It gives them up as soon as the capture handle is open and runs
the rest of the session as the invoking user. The terminal belongs to
the display once it is up, so errors go to syslog rather than the
screen: check there if potion seems to be doing nothing.

See `man potion` for the full description.

## History

I wrote potion in 2004, and it was in Debian until it fell out of the
archive. Release 0.1.1 is the first in over a decade. It drops my own
`libabz` and `libdebug` libraries in favour of libc, fixes a set of
memory-safety bugs in the packet parser, corrects flow eviction and
fragment handling, drops privileges after opening the capture handle,
and modernises the build and the packaging. The changelog in
`debian/changelog` has the details.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
