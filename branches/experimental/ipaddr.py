#!/usr/bin/python
#
# Copyright 2007 Google Inc.
#  Licensed to PSF under a Contributor Agreement.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""An IPv4/IPv6 manipulation library in Python.

This library is used to create/poke/manipulate IPv4 and IPv6 addresses
and networks.

"""

__version__ = 'trunk'

import struct

class Error(Exception):

    """Base class for exceptions."""


class IPTypeError(Error):

    """Tried to perform a v4 action on v6 object or vice versa."""


class IPAddressExclusionError(Error):

    """An Error we should never see occurred in address exclusion."""


class IPAddressIPValidationError(Error):

    """Raised when a single address (v4 or v6) was given a network."""

    def __init__(self, ip):
        Error.__init__(self)
        self._ip = ip

    def __str__(self):
        return "%s is not a valid address (hint, it's probably a network)" % (
            repr(self._ip))

class IPv4IpValidationError(Error):

    """Raised when an IPv4 address is invalid."""

    def __init__(self, ip):
        Error.__init__(self)
        self._ip = ip

    def __str__(self):
        return repr(self._ip) + ' is not a valid IPv4 address'

class IPv4NetmaskValidationError(Error):

    """Raised when a netmask is invalid."""

    def __init__(self, netmask):
        Error.__init__(self)
        self.netmask = netmask

    def __str__(self):
        return repr(self.netmask) + ' is not a valid IPv4 netmask'


class IPv6IpValidationError(Error):

    """Raised when an IPv6 address is invalid."""

    def __init__(self, ip):
        Error.__init__(self)
        self._ip = ip

    def __str__(self):
        return repr(self._ip) + ' is not a valid IPv6 network'


class IPv6NetmaskValidationError(Error):

    """Raised when an IPv6 netmask is invalid."""

    def __init__(self, netmask):
        Error.__init__(self)
        self.netmask = netmask

    def __str__(self):
        return repr(self.netmask) + ' is not a valid IPv6 netmask'


class PrefixlenDiffInvalidError(Error):

    """Raised when Sub/Supernets is called with a bad prefixlen_diff."""

    def __init__(self, error_str):
        Error.__init__(self)
        self.error_str = error_str


def IP(address, host=False, version=None):
    """Take an IP string/int and return an object of the correct type.

    Args:
        ip_str: A string or integer, the IP address.  Either IPv4 or
          IPv6 addresses may be supplied; integers less than 2**32 will
          be considered to be IPv4.
        host: A bool indicating that a host rather than the default network
          object should be created.
        version: An Integer, if set, don't try to automatically
          determine what the IP address type is. important for things
          like IP(1), which could be IPv4 or IPv6.

    Returns:
        An IPv4 or IPv6 object.

    Raises:
        ValueError: if the string passed isn't either a v4 or a v6
          address.

    """
    if version:
        if version == 4:
            return IPv4(address, host=host)
        elif version == 6:
            return IPv6(address, host=host)

    try:
        return IPv4(address, host=host)
    except (IPv4IpValidationError, IPv4NetmaskValidationError):
        pass

    try:
        return IPv6(address, host=host)
    except (IPv6IpValidationError, IPv6NetmaskValidationError):
        pass

    raise ValueError('%r does not appear to be an IPv4 or IPv6 address' %
                     address)


def _collapse_address_list_recursive(addresses):
    """Loops through the addresses, collapsing concurrent netblocks.

    Example:

        ip1 = IPv4('1.1.0.0/24')
        ip2 = IPv4('1.1.1.0/24')
        ip3 = IPv4('1.1.2.0/24')
        ip4 = IPv4('1.1.3.0/24')
        ip5 = IPv4('1.1.4.0/24')
        ip6 = IPv4('1.1.0.1/22')

        _collapse_address_list_recursive([ip1, ip2, ip3, ip4, ip5, ip6]) ->
          [IPv4('1.1.0.0/22'), IPv4('1.1.4.0/24')]

        This shouldn't be called directly; it is called via
          collapse_address_list([]).

    Args:
        addresses: A list of IPv4 or IPv6 objects.

    Returns:
        A list of IPv4 or IPv6 objects depending on what we were passed.

    """
    ret_array = []
    optimized = False

    for cur_addr in addresses:
        if not ret_array:
            ret_array.append(cur_addr)
            continue
        if cur_addr in ret_array[-1]:
            optimized = True
        elif cur_addr == ret_array[-1].supernet().subnet()[1]:
            ret_array.append(ret_array.pop().supernet())
            optimized = True
        else:
            ret_array.append(cur_addr)

    if optimized:
        return _collapse_address_list_recursive(ret_array)

    return ret_array


def collapse_address_list(addresses):
    """Collapse a list of IP objects.

    Example:
        collapse_address_list([IPv4('1.1.0.0/24'), IPv4('1.1.1.0/24')]) ->
          [IPv4('1.1.0.0/23')]

    Args:
        addresses: A list of IPv4 or IPv6 objects.

    Returns:
        A list of IPv4 or IPv6 objects depending on what we were passed.

    """
    return _collapse_address_list_recursive(
        sorted(addresses, key=BaseNet._get_networks_key))

# backwards compatibility
CollapseAddrList = collapse_address_list

# Test whether this Python implementation supports byte objects that
# are not identical to str ones.
# We need to exclude platforms where bytes == str so that we can
# distinguish between packed representations and strings, for example
# b'12::' (the IPv4 address 49.50.58.58) and '12::' (an IPv6 address).
try:
    _compat_has_real_bytes = bytes != str
except NameError: # <Python2.6
    _compat_has_real_bytes = False


class IPAddrBase(object):

    """The mother class."""

    def __index__(self):
        return self._ip

    def __int__(self):
        return self._ip

    def __hex__(self):
        return hex(self._ip)


class BaseIP(IPAddrBase):

    """A generic IP object.

    This IP class contains the version independent methods which are
    used by single IP addresses.

    """

    @property
    def exploded(self):
        return self._explode_shorthand_ip_string()

    @property
    def compressed(self):
        return str(self)

    def __init__(self, address):
        if '/' in str(address):
            raise IPAddressIPValidationError(address)

    def __eq__(self, other):
        try:
            return not (self._ip != other._ip
                        or self._version != other._version)
        except AttributeError:
            return NotImplemented

    def __ne__(self, other):
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __le__(self, other):
        gt = self.__gt__(other)
        if gt is NotImplemented:
            return NotImplemented
        return not gt

    def __ge__(self, other):
        lt = self.__lt__(other)
        if lt is NotImplemented:
            return NotImplemented
        return not lt

    def __lt__(self, other):
        if self._version != other._version:
            return self._version < other._version
        if self._ip != other._ip:
            return self._ip < other._ip
        return False

    def __gt__(self, other):
        if self._version != other._version:
            return self._version > other._version
        if self._ip != other._ip:
            return self._ip > other._ip
        return False

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

    def __str__(self):
        return  '%s' % self._string_from_ip_int(self._ip)

    @property
    def version(self):
        raise NotImplementedError('BaseIP has no version')


class BaseNet(IPAddrBase):

    """A generic IP object.

    This IP class contains the version independent methods which are
    used by networks.

    """

    def __init__(self, address):
        self._cache = {}

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

    def iterhosts(self):
        """Generate Iterator over hosts in a network."""
        cur = int(self.network)
        bcast = int(self.broadcast)
        while cur <= bcast:
            cur += 1
            yield IP(cur - 1, host=True, version=self._version)

    def __iter__(self):
        self._cur = int(self.network)
        return self

    def next(self):
        if self._cur > int(self.broadcast):
            raise StopIteration
        self._cur += 1
        return IP(self._cur - 1, host=True, version=self._version)

    def __getitem__(self, n):
        network = int(self.network)
        broadcast = int(self.broadcast)
        if n >= 0:
            if network + n > broadcast:
                raise IndexError
            return IP(network + n, host=True, version=self._version)
        else:
            n += 1
            if broadcast + n < network:
                raise IndexError
            return IP(broadcast + n, host=True,
                      version=self._version)

    def __lt__(self, other):
        try:
            if self._version != other._version:
                return self._version < other._version
            if self._ip != other._ip:
                return self._ip < other._ip
            if self.netmask != other.netmask:
                return self.netmask < other.netmask
            return False
        except AttributeError:
            return NotImplemented

    def __gt__(self, other):
        try:
            if self._version != other._version:
                return self._version > other._version
            if self._ip != other._ip:
                return self._ip > other._ip
            if self.netmask != other.netmask:
                return self.netmask > other.netmask
            return False
        except AttributeError:
            return NotImplemented

    def __eq__(self, other):
        try:
            return (self._version == other._version
                    and self._ip == other._ip
                    and int(self.netmask) == int(other.netmask))
        except AttributeError:
            return NotImplemented

    def __ne__(self, other):
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __str__(self):
        return  '%s/%s' % (str(self.ip),
                           str(self._prefixlen))

    def __hash__(self):
        return hash(self._ip ^ int(self.netmask))

    def __contains__(self, other):
        # Easy case, dealing with networks.
        if isinstance(other, IPv4Network) or isinstance(other, IPv6Network):
            return (int(self.network) <= int(other._ip) and
                    int(self.broadcast) >= int(other.broadcast))
        elif isinstance(other, IPv4Address) or isinstance(other, IPv6Address):
            # Check if we've got an Address
            return (int(self.network) <= int(other._ip) <=
                    int(self.broadcast))
        else:
            return IP(other) in self

    @property
    def network(self):
        x = self._cache.get('network')
        if x is None:
            x = IP(self._ip & int(self.netmask), host=True,
                   version=self._version)
            self._cache['network'] = x
        return x

    @property
    def broadcast(self):
        x = self._cache.get('broadcast')
        if x is None:
            x = IP(self._ip | int(self.hostmask), host=True,
                   version=self._version)
            self._cache['broadcast'] = x
        return x

    @property
    def hostmask(self):
        x = self._cache.get('hostmask')
        if x is None:
            x = IP(int(self.netmask) ^ self._ALL_ONES, host=True,
                   version=self._version)
            self._cache['hostmask'] = x
        return x

    @property
    def with_prefixlen(self):
        return '%s/%d' % (str(self.ip), self._prefixlen)

    @property
    def with_netmask(self):
        return '%s/%s' % (str(self.ip), str(self.netmask))

    @property
    def with_hostmask(self):
        return '%s/%s' % (str(self.ip), str(self.hostmask))

    @property
    def numhosts(self):
        """Number of hosts in the current subnet."""
        return int(self.broadcast) - int(self.network) + 1

    @property
    def version(self):
        raise NotImplementedError('BaseNet has no version')

    prefixlen = property(
        fget=lambda self: self._prefixlen,
        fset=lambda self, prefixlen: self._set_prefix(prefixlen))

    def address_exclude(self, other):
        """Remove an address from a larger block.

        For example:

            addr1 = IP('10.1.1.0/24')
            addr2 = IP('10.1.1.0/26')
            addr1.address_exclude(addr2) =
                [IP('10.1.1.64/26'), IP('10.1.1.128/25')]

        or IPv6:

            addr1 = IP('::1/32')
            addr2 = IP('::1/128')
            addr1.address_exclude(addr2) = [IP('::0/128'),
                IP('::2/127'),
                IP('::4/126'),
                IP('::8/125'),
                ...
                IP('0:0:8000::/33')]

        Args:
            other: An IP object of the same type.

        Returns:
            A sorted list of IP objects addresses which is self minus
            other.

        Raises:
            IPTypeError: If self and other are of difffering address
              versions.
            IPAddressExclusionError: There was some unknown error in the
              address exclusion process.  This likely points to a bug
              elsewhere in this code.
            ValueError: If other is not completely contained by self.

        """
        if not self._version == other._version:
            raise IPTypeError("%s and %s aren't of the same version" % (
                str(self), str(other)))

        if other not in self:
            raise ValueError('%s not contained in %s' % (str(other),
                                                         str(self)))
        ret_addrs = []

        # Make sure we're comparing the network of other.
        other = IP('%s/%s' % (str(other.network), str(other.prefixlen)),
                   version=other._version)

        s1, s2 = self.subnet()
        while s1 != other and s2 != other:
            if other in s1:
                ret_addrs.append(s2)
                s1, s2 = s1.subnet()
            elif other in s2:
                ret_addrs.append(s1)
                s1, s2 = s2.subnet()
            else:
                # If we got here, there's a bug somewhere.
                raise IPAddressExclusionError('Error performing exclusion: '
                                              's1: %s s2: %s other: %s' %
                                              (str(s1), str(s2), str(other)))
        if s1 == other:
            ret_addrs.append(s2)
        elif s2 == other:
            ret_addrs.append(s1)
        else:
            # If we got here, there's a bug somewhere.
            raise IPAddressExclusionError('Error performing exclusion: '
                                          's1: %s s2: %s other: %s' %
                                          (str(s1), str(s2), str(other)))

        return sorted(ret_addrs, key=BaseNet._get_networks_key)

    def compare_networks(self, other):
        """Compare two IP objects.

        This is only concerned about the comparison of the integer
        representation of the network addresses.  This means that the
        host bits aren't considered at all in this method.  If you want
        to compare host bits, you can easily enough do a
        'HostA._ip < HostB._ip'

        Args:
            other: An IP object.

        Returns:
            If the IP versions of self and other are the same, returns:

            -1 if self < other:
              eg: IPv4('1.1.1.0/24') < IPv4('1.1.2.0/24')
              IPv6('1080::200C:417A') < IPv6('1080::200B:417B')
            0 if self == other
              eg: IPv4('1.1.1.1/24') == IPv4('1.1.1.2/24')
              IPv6('1080::200C:417A/96') == IPv6('1080::200C:417B/96')
            1 if self > other
              eg: IPv4('1.1.1.0/24') > IPv4('1.1.0.0/24')
              IPv6('1080::1:200C:417A/112') >
              IPv6('1080::0:200C:417A/112')

            If the IP versions of self and other are different, returns:

            -1 if self._version < other._version
              eg: IPv4('10.0.0.1/24') < IPv6('::1/128')
            1 if self._version > other._version
              eg: IPv6('::1/128') > IPv4('255.255.255.0/24')

        """
        if self._version < other._version:
            return -1
        if self._version > other._version:
            return 1
        # self._version == other._version below here:
        if self.network < other.network:
            return -1
        if self.network > other.network:
            return 1
        # self.network == other.network below here:
        if self.netmask < other.netmask:
            return -1
        if self.netmask > other.netmask:
            return 1
        # self.network == other.network and self.netmask == other.netmask
        return 0

    def _get_networks_key(self):
        """Network-only key function.

        Returns an object that identifies this address' network and
        netmask. This function is a suitable "key" argument for sorted()
        and list.sort().

        """
        return (self._version, self.network, self.netmask)

    def _ip_int_from_prefix(self, prefixlen=None):
        """Turn the prefix length netmask into a int for comparison.

        Args:
            prefixlen: An integer, the prefix length.

        Returns:
            An integer.

        """
        if not prefixlen and prefixlen != 0:
            prefixlen = self._prefixlen
        return self._ALL_ONES ^ (self._ALL_ONES >> prefixlen)

    def _prefix_from_ip_int(self, ip_int, mask=32):
        """Return prefix length from the decimal netmask.

        Args:
            ip_int: An integer, the IP address.
            mask: The netmask.  Defaults to 32.

        Returns:
            An integer, the prefix length.

        """
        while mask:
            if ip_int & 1 == 1:
                break
            ip_int >>= 1
            mask -= 1

        return mask

    def _ip_string_from_prefix(self, prefixlen=None):
        """Turn a prefix length into a dotted decimal string.

        Args:
            prefixlen: An integer, the netmask prefix length.

        Returns:
            A string, the dotted decimal netmask string.

        """
        if not prefixlen:
            prefixlen = self._prefixlen
        return self._string_from_ip_int(self._ip_int_from_prefix(prefixlen))

    # backwards compatibility
    AddressExclude = address_exclude
    CompareNetworks = compare_networks
    Contains = __contains__
    def set_prefix(self, prefixlen): self.prefixlen = prefixlen
    SetPrefix = set_prefix
    def get_prefix(self): return self.prefixlen


class BaseV4(object):

    """Base IPv4 object.

    The following methods are used by IPv4 objects in both single IP
    addresses and networks.

    """

    # Equivalent to 255.255.255.255 or 32 bits of 1's.
    _ALL_ONES = (2**32) - 1

    def __init__(self, address):
        self._version = 4

    def _explode_shorthand_ip_string(self, ip_str=None):
        if not ip_str:
            ip_str = str(self)
        return ip_str

    def _ip_int_from_string(self, ip_str):
        """Turn the given IP string into an integer for comparison.

        Args:
            ip_str: A string, the IP ip_str.

        Returns:
            The IP ip_str as an integer.

        """
        packed_ip = 0
        for oc in ip_str.split('.'):
            packed_ip = (packed_ip << 8) | int(oc)
        return packed_ip

    def _string_from_ip_int(self, ip_int):
        """Turns a 32-bit integer into dotted decimal notation.

        Args:
            ip_int: An integer, the IP address.

        Returns:
            The IP address as a string in dotted decimal notation.

        """
        octets = []
        for _ in xrange(4):
            octets.insert(0, str(ip_int & 0xFF))
            ip_int >>= 8
        return '.'.join(octets)

    def _is_valid_ip(self, ip_str):
        """Validate the dotted decimal notation IP/netmask string.

        Args:
            ip_str: A string, the IP ip_str.

        Returns:
            A boolean, True if the string is a valid dotted decimal IP
            string.

        """
        octets = ip_str.split('.')
        if len(octets) == 1:
            # We have an integer rather than a dotted decimal IP.
            try:
                return int(ip_str) >= 0 and int(ip_str) <= self._ALL_ONES
            except ValueError:
                return False

        if len(octets) != 4:
            return False

        for octet in octets:
            try:
                if not 0 <= int(octet) <= 255:
                    return False
            except ValueError:
                return False
        return True

    @property
    def packed(self):
        """The binary representation of this address."""
        return struct.pack('!I', self._ip)

    @property
    def version(self):
        return self._version


class IPv4Address(BaseIP, BaseV4):

    """Represent and manipulate single IPv4 Addresses."""

    def __init__(self, address):

        """
        Args:
            address: A string or integer representing the IP
              '192.168.1.1'

              Additionally, an integer can be passed, so
              IPv4Address('192.168.1.1') == IPv4Address(3232235777).
              or, more generally
              IPv4Address(int(IPv4Address('192.168.1.1'))) ==
                IPv4Address('192.168.1.1')

        Raises:
            IPv4IpValidationError: If ipaddr isn't a valid IPv4 address.
            IPv4NetmaskValidationError: If the netmask isn't valid for
              an IPv4 address.

        """
        BaseIP.__init__(self, address)
        BaseV4.__init__(self, address)

        # Efficient constructor from integer.
        if isinstance(address, int) or isinstance(address, long):
            self._ip = address
            if address < 0 or address > self._ALL_ONES:
                raise IPv4IpValidationError(address)
            return

        # Constructing from a packed address
        if _compat_has_real_bytes:
            if isinstance(address, bytes) and len(address) == 4:
                self._ip = struct.unpack('!I', address)[0]
                return

        # we have a string
        if not self._is_valid_ip(address):
            raise IPv4IpValidationError(address)

        self._ip = self._ip_int_from_string(address)


class IPv4Network(BaseV4, BaseNet):

    """This class represents and manipulates 32-bit IPv4 networks.

    Attributes: [examples for IPv4Network('1.2.3.4/27')]
        ._ip: 16909060
        .ip: IPv4Address('1.2.3.4')
        .network: IPv4Address('1.2.3.0')
        .hostmask: IPv4Address('0.0.0.31')
        .broadcast: IPv4Address('1.2.3.31')
        .netmask: IPv4Address('255.255.255.224')
        .prefixlen: 27

    """

    def __init__(self, address):
        """Instantiate a new IPv4 network object.

        Args:
            address: A string or integer representing the IP [& network].
              '192.168.1.1/32'
              '192.168.1.1/255.255.255.255'
              '192.168.1.1/0.0.0.255'
              '192.168.1.1'
              are all functionally the same in IPv4. That is to say,
              failing to provide a subnetmask will create an object with
              a mask of /32. A netmask of '255.255.255.255' is assumed
              to be /32 and '0.0.0.0' is assumed to be /0, even though
              other netmasks can be expressed both as host- and
              net-masks. (255.0.0.0 == 0.255.255.255)

              Additionally, an integer can be passed, so
              IPv4Network('192.168.1.1') == IPv4Network(3232235777).
              or, more generally
              IPv4Network(int(IPv4Network('192.168.1.1'))) ==
                IPv4Network('192.168.1.1')

        Raises:
            IPv4IpValidationError: If ipaddr isn't a valid IPv4 address.
            IPv4NetmaskValidationError: If the netmask isn't valid for
              an IPv4 address.

        """
        BaseNet.__init__(self, address)
        BaseV4.__init__(self, address)

        # Efficient constructor from integer.
        if isinstance(address, int) or isinstance(address, long):
            self._ip = address
            self.ip = IPv4Address(self._ip)
            self._prefixlen = 32
            self.netmask = IPv4Address(self._ALL_ONES)
            if address < 0 or address > self._ALL_ONES:
                raise IPv4IpValidationError(address)
            return

        # Constructing from a packed address
        if _compat_has_real_bytes:
            if isinstance(address, bytes) and len(address) == 4:
                self._ip = struct.unpack('!I', address)[0]
                self.ip = IPv4Address(self._ip)
                self._prefixlen = 32
                self.netmask = IPv4Address(self._ALL_ONES)
                return

        # Assume input argument to be string or any object representation
        # which converts into a formatted IP prefix string.
        addr = str(address).split('/')

        if len(addr) > 2:
            raise IPv4IpValidationError(address)

        if not self._is_valid_ip(addr[0]):
            raise IPv4IpValidationError(addr[0])

        self._ip = self._ip_int_from_string(addr[0])
        self.ip = IPv4Address(self._ip)

        if len(addr) == 2:
            mask = addr[1].split('.')
            if len(mask) == 4:
                # We have dotted decimal netmask.
                if not self._is_valid_netmask(addr[1]):
                    raise IPv4NetmaskValidationError(addr[1])
                if self._is_hostmask(addr[1]):
                    self.netmask = IPv4Address(
                        self._ip_int_from_string(addr[1]) ^ self._ALL_ONES)
                else:
                    self.netmask = IPv4Address(self._ip_int_from_string(
                        addr[1]))

                self._prefixlen = self._prefix_from_ip_int(int(self.netmask))
            else:
                # We have a netmask in prefix length form.
                if not self._is_valid_netmask(addr[1]):
                    raise IPv4NetmaskValidationError(addr[1])
                self._prefixlen = int(addr[1])
                self.netmask = IPv4Address(self._ip_int_from_prefix(
                    self._prefixlen))
        else:
            self._prefixlen = 32
            self.netmask = IPv4Address(self._ip_int_from_prefix(
                self._prefixlen))


    def _set_prefix(self, prefixlen):
        """Change the prefix length of an IPv4 network object.

        Args:
            prefixlen: An integer, the new prefix length.

        Raises:
            IPv4NetmaskValidationError: If prefixlen is out of bounds.

        """
        if not 0 <= prefixlen <= 32:
            raise IPv4NetmaskValidationError(prefixlen)
        self._prefixlen = prefixlen
        self.netmask = IPv4Address(self._ip_int_from_prefix(self._prefixlen))
        # invalidate the element cache
        self._cache['network'] = None
        self._cache['hostmask'] = None
        self._cache['broadcast'] = None

    def subnet(self, prefixlen_diff=1):
        """The subnets which join to make the current subnet.

        In the case that self contains only one IP
        (self._prefixlen == 32), return a list with just ourself.

        Args:
            prefixlen_diff: An integer, the amount the prefix length
              should be increased by.  Given a /24 network and a
              prefixlen_diff of 3, for example, 8 subnets of size /27
              will be returned.  The default value of 1 splits the
              current network into two halves.

        Returns:
            A list of IPv4 network objects.

        Raises:
            PrefixlenDiffInvalidError: The prefixlen_diff is too small
              or too large.

        """
        if self._prefixlen == 32:
            return [self]

        if prefixlen_diff < 0:
            raise PrefixlenDiffInvalidError('prefix length diff must be > 0')
        new_prefixlen = self._prefixlen + prefixlen_diff

        if not self._is_valid_netmask(str(new_prefixlen)):
            raise PrefixlenDiffInvalidError(
                'prefix length diff %d is invalid for netblock %s' % (
                    new_prefixlen, str(self)))

        first = IPv4('%s/%s' % (str(self.network),
                                str(self._prefixlen + prefixlen_diff)))
        subnets = [first]
        current = first
        while True:
            broadcast = current.broadcast
            if broadcast == self.broadcast:
                break
            current = IPv4('%d/%s' % (int(broadcast) + 1, str(new_prefixlen)))
            subnets.append(current)

        return subnets

    def supernet(self, prefixlen_diff=1):
        """The supernet containing the current network.

        Args:
            prefixlen_diff: An integer, the amount the prefix length of
              the network should be decreased by.  For example, given a
              /24 network and a prefixlen_diff of 3, a supernet with a
              /21 netmask is returned.

        Returns:
            An IPv4 network object.

        Raises:
            PrefixlenDiffInvalidError: If
              self.prefixlen - prefixlen_diff < 0. I.e., you have a
              negative prefix length.

        """
        if self._prefixlen == 0:
            return self
        if self.prefixlen - prefixlen_diff < 0:
            raise PrefixlenDiffInvalidError(
                'current prefixlen is %d, cannot have a prefixlen_diff of %d' %
                (self.prefixlen, prefixlen_diff))
        return IPv4('%s/%s' % (str(self.network),
                               str(self.prefixlen - prefixlen_diff)))

    @property
    def is_private(self):
        """Test if this address is allocated for private networks.

        Returns:
            A boolean, True if the address is reserved per RFC 1918.

        """
        return (self in IPv4('10.0.0.0/8') or
                self in IPv4('172.16.0.0/12') or
                self in IPv4('192.168.0.0/16'))

    @property
    def is_multicast(self):
        """Test if the address is reserved for multicast use.

        Returns:
            A boolean, True if the address is multicast.
            See RFC 3171 for details.

        """
        return self in IPv4('224.0.0.0/4')

    @property
    def is_loopback(self):
        """Test if the address is a loopback adddress.

        Returns:
            A boolean, True if the address is a loopback per RFC 3330.

        """
        return self in IPv4('127.0.0.0/8')

    @property
    def is_link_local(self):
        """Test if the address is reserved for link-local.

        Returns:
            A boolean, True if the address is link-local per RFC 3927.

        """
        return self in IPv4('169.254.0.0/16')

    def _is_hostmask(self, ip_str):
        """Test if the IP string is a hostmask (rather than a netmask).

        Args:
            ip_str: A string, the potential hostmask.

        Returns:
            A boolean, True if the IP string is a hostmask.

        """
        parts = [int(x) for x in ip_str.split('.')]
        if parts[0] < parts[-1]:
            return True
        return False

    def _is_valid_netmask(self, netmask):
        """Verify that the netmask is valid.

        Args:
            netmask: A string, either a prefix or dotted decimal
              netmask.

        Returns:
            A boolean, True if the prefix represents a valid IPv4
            netmask.

        """
        if len(netmask.split('.')) == 4:
            return self._is_valid_ip(netmask)
        try:
            netmask = int(netmask)
        except ValueError:
            return False
        return 0 <= netmask <= 32

    # backwards compatibility
    Subnet = subnet
    Supernet = supernet
    IsRFC1918 = lambda self: self.is_private
    IsMulticast = lambda self: self.is_multicast
    IsLoopback = lambda self: self.is_loopback
    IsLinkLocal = lambda self: self.is_link_local


class IPv4(object):
    """Generic IPv4 selector class.

    Return a single IP or a network object based on the kwargs.
    """
    def __new__(cls, *args, **kwargs):
        if not args:
            return False
        if kwargs.has_key('host') and kwargs['host']:
            return IPv4Address(args[0])
        else:
            return IPv4Network(args[0])


class BaseV6(object):

    """Base IPv6 object.

    The following methods are used by IPv6 objects in both single IP
    addresses and networks.

    """

    _ALL_ONES = (2**128) - 1

    def __init__(self, address):
        self._version = 6

    def _ip_int_from_string(self, ip_str=None):
        """Turn an IPv6 ip_str into an integer.

        Args:
            ip_str: A string, the IPv6 ip_str.

        Returns:
            A long, the IPv6 ip_str.

        """
        if not ip_str:
            ip_str = str(self.ip)

        ip_int = 0

        fields = self._explode_shorthand_ip_string(ip_str).split(':')

        # Do we have an IPv4 mapped (::ffff:a.b.c.d) or compact (::a.b.c.d)
        # ip_str?
        if fields[-1].count('.') == 3:
            ipv4_string = fields.pop()
            ipv4_int = IPv4(ipv4_string)._ip
            octets = []
            for _ in xrange(2):
                octets.append(hex(ipv4_int & 0xFFFF).lstrip('0x').rstrip('L'))
                ipv4_int >>= 16
            fields.extend(reversed(octets))

        for field in fields:
            ip_int = (ip_int << 16) + int(field, 16)

        return ip_int

    def _compress_hextets(self, hextets):
        """Compresses a list of hextets.

        Compresses a list of strings, replacing the longest continuous
        sequence of "0" in the list with "" and adding empty strings at
        the beginning or at the end of the string such that subsequently
        calling ":".join(hextets) will produce the compressed version of
        the IPv6 address.

        Args:
            hextets: A list of strings, the hextets to compress.

        Returns:
            A list of strings.

        """
        best_doublecolon_start = -1
        best_doublecolon_len = 0
        doublecolon_start = -1
        doublecolon_len = 0
        for index in range(len(hextets)):
            if hextets[index] == '0':
                doublecolon_len += 1
                if doublecolon_start == -1:
                    # Start of a sequence of zeros.
                    doublecolon_start = index
                if doublecolon_len > best_doublecolon_len:
                    # This is the longest sequence of zeros so far.
                    best_doublecolon_len = doublecolon_len
                    best_doublecolon_start = doublecolon_start
            else:
                doublecolon_len = 0
                doublecolon_start = -1

        if best_doublecolon_len > 1:
            best_doublecolon_end = (best_doublecolon_start +
                                    best_doublecolon_len)
            # For zeros at the end of the address.
            if best_doublecolon_end == len(hextets):
                hextets += ['']
            hextets[best_doublecolon_start:best_doublecolon_end] = ['']
            # For zeros at the beginning of the address.
            if best_doublecolon_start == 0:
                hextets = [''] + hextets

        return hextets

    def _string_from_ip_int(self, ip_int=None):
        """Turns a 128-bit integer into hexadecimal notation.

        Args:
            ip_int: An integer, the IP address.

        Returns:
            A string, the hexadecimal representation of the address.

        Raises:
            ValueError: The address is bigger than 128 bits of all ones.

        """
        if not ip_int and ip_int != 0:
            ip_int = int(self._ip)

        if ip_int > self._ALL_ONES:
            raise ValueError('IPv6 address is too large')

        hex_str = '%032x' % ip_int
        hextets = []
        for x in range(0, 32, 4):
            hextets.append('%x' % int(hex_str[x:x+4], 16))

        hextets = self._compress_hextets(hextets)
        return ':'.join(hextets)

    def _explode_shorthand_ip_string(self, ip_str=None):
        """Expand a shortened IPv6 address.

        Args:
            ip_str: A string, the IPv6 address.

        Returns:
            A string, the expanded IPv6 address.

        """
        if not ip_str:
            ip_str = str(self)

        if self._is_shorthand_ip(ip_str):
            new_ip = []
            hextet = ip_str.split('::')
            sep = len(hextet[0].split(':')) + len(hextet[1].split(':'))
            new_ip = hextet[0].split(':')

            for _ in xrange(8 - sep):
                new_ip.append('0000')
            new_ip += hextet[1].split(':')

            # Now need to make sure every hextet is 4 lower case characters.
            # If a hextet is < 4 characters, we've got missing leading 0's.
            ret_ip = []
            for hextet in new_ip:
                ret_ip.append(('0' * (4 - len(hextet)) + hextet).lower())
            return ':'.join(ret_ip)
        # We've already got a longhand ip_str.
        return ip_str

    def _is_valid_ip(self, ip_str):
        """Ensure we have a valid IPv6 address.

        Probably not as exhaustive as it should be.

        Args:
            ip_str: A string, the IPv6 address.

        Returns:
            A boolean, True if this is a valid IPv6 address.

        """
        # We need to have at least one ':'.
        if ':' not in ip_str:
            return False

        # We can only have one '::' shortener.
        if ip_str.count('::') > 1:
            return False

        # '::' should be encompassed by start, digits or end.
        if ':::' in ip_str:
            return False

        # A single colon can neither start nor end an address.
        if ((ip_str.startswith(':') and not ip_str.startswith('::')) or
                (ip_str.endswith(':') and not ip_str.endswith('::'))):
            return False

        # If we have no concatenation, we need to have 8 fields with 7 ':'.
        if '::' not in ip_str and ip_str.count(':') != 7:
            # We might have an IPv4 mapped address.
            if ip_str.count('.') != 3:
                return False

        ip_str = self._explode_shorthand_ip_string(ip_str)

        # Now that we have that all squared away, let's check that each of the
        # hextets are between 0x0 and 0xFFFF.
        for hextet in ip_str.split(':'):
            if hextet.count('.') == 3:
                # If we have an IPv4 mapped address, the IPv4 portion has to be
                # at the end of the IPv6 portion.
                if not ip_str.split(':')[-1] == hextet:
                    return False
                try:
                    IPv4(hextet)
                except IPv4IpValidationError:
                    return False
            elif int(hextet, 16) < 0x0 or int(hextet, 16) > 0xFFFF:
                return False
        return True

    def _is_shorthand_ip(self, ip_str=None):
        """Determine if the address is shortened.

        Args:
            ip_str: A string, the IPv6 address.

        Returns:
            A boolean, True if the address is shortened.

        """
        if ip_str.count('::') == 1:
            return True
        return False

    @property
    def packed(self):
        """The binary representation of this address."""
        return struct.pack('!QQ', self._ip >> 64, self._ip & (2**64 - 1))

    @property
    def version(self):
        return self._version


class IPv6Address(BaseV6, BaseIP):

    """Represent and manipulate single IPv6 Addresses.
    """

    def __init__(self, address):
        """Instantiate a new IPv6 address object.

        Args:
            address: A string or integer representing the IP

              Additionally, an integer can be passed, so
              IPv6Address('2001:4860::') ==
                IPv6Address(42541956101370907050197289607612071936L).
              or, more generally
              IPv6Address(IPv6Address('2001:4860::')._ip) ==
                IPv6Address('2001:4860::')


        Raises:
            IPv6IpValidationError: If address isn't a valid IPv6 address.
            IPv6NetmaskValidationError: If the netmask isn't valid for
              an IPv6 address.

        """
        BaseIP.__init__(self, address)
        BaseV6.__init__(self, address)

        # Efficient constructor from integer.
        if isinstance(address, long) or isinstance(address, int):
            self._ip = address
            if address < 0 or address > self._ALL_ONES:
                raise IPv6IpValidationError(address)
            return

        # Constructing from a packed address
        if _compat_has_real_bytes:
            if isinstance(address, bytes) and len(address) == 16:
                tmp = struct.unpack('!QQ', address)
                self._ip = (tmp[0] << 64) | tmp[1]
                return

        # Assume input argument to be string or any object representation
        # which converts into a formatted IP prefix string.
        addr_str = str(address)
        if not addr_str:
            raise IPv6IpValidationError('')

        self._ip = self._ip_int_from_string(address)


class IPv6Network(BaseV6, BaseNet):

    """This class represents and manipulates 128-bit IPv6 networks.

    Attributes: [examples for IPv6('2001:658:22A:CAFE:200::1/64')]
        .ip: IPv6Address('2001:658:22a:cafe:200::1')
        .network: IPv6Address('2001:658:22a:cafe::')
        .hostmask: IPv6Address('::ffff:ffff:ffff:ffff')
        .broadcast: IPv6Address('2001:658:22a:cafe:ffff:ffff:ffff:ffff')
        .netmask: IPv6Address('ffff:ffff:ffff:ffff::')
        .prefixlen: 64

    """


    def __init__(self, address):
        """Instantiate a new IPv6 Network object.

        Args:
            address: A string or integer representing the IPv6 network or the IP
              and prefix/netmask.
              '2001:4860::/128'
              '2001:4860:0000:0000:0000:0000:0000:0000/128'
              '2001:4860::'
              are all functionally the same in IPv6.  That is to say,
              failing to provide a subnetmask will create an object with
              a mask of /128.

              Additionally, an integer can be passed, so
              IPv6Network('2001:4860::') ==
                IPv6Network(42541956101370907050197289607612071936L).
              or, more generally
              IPv6Network(IPv6Network('2001:4860::')._ip) ==
                IPv6Network('2001:4860::')

        Raises:
            IPv6IpValidationError: If address isn't a valid IPv6 address.
            IPv6NetmaskValidationError: If the netmask isn't valid for
              an IPv6 address.

        """
        BaseNet.__init__(self, address)
        BaseV6.__init__(self, address)

        # Efficient constructor from integer.
        if isinstance(address, long) or isinstance(address, int):
            self._ip = address
            self.ip = IPv6Address(self._ip)
            self._prefixlen = 128
            self.netmask = IPv6Address(self._ALL_ONES)
            if address < 0 or address > self._ALL_ONES:
                raise IPv6IpValidationError(address)
            return

        # Constructing from a packed address
        if _compat_has_real_bytes:
            if isinstance(address, bytes) and len(address) == 16:
                tmp = struct.unpack('!QQ', address)
                self._ip = (tmp[0] << 64) | tmp[1]
                self.ip = IPv6Address(self._ip)
                self._prefixlen = 128
                self.netmask = IPv6Address(self._ALL_ONES)
                return

        # Assume input argument to be string or any object representation
        # which converts into a formatted IP prefix string.
        addr = str(address).split('/')

        if len(addr) > 2:
            raise IPv6IpValidationError(ipaddr)

        if not self._is_valid_ip(addr[0]):
            raise IPv6IpValidationError(addr[0])

        if len(addr) == 2:
            if self._is_valid_netmask(addr[1]):
                self._prefixlen = int(addr[1])
            else:
                raise IPv6NetmaskValidationError(addr[1])
        else:
            self._prefixlen = 128

        self.netmask = IPv6Address(self._ip_int_from_prefix(self._prefixlen))

        if not self._is_valid_ip(addr[0]):
            raise IPv6IpValidationError(addr[0])

        self._ip = self._ip_int_from_string(addr[0])
        self.ip = IPv6Address(self._ip)

    def _set_prefix(self, prefixlen):
        """Change the prefix length.

        Args:
            prefixlen: An integer, the new prefix length.

        Raises:
            IPv6NetmaskValidationError: If prefixlen is out of bounds.

        """
        if not 0 <= prefixlen <= 128:
            raise IPv6NetmaskValidationError(prefixlen)
        self._prefixlen = prefixlen
        self.netmask = self._ip_int_from_prefix(self.prefixlen)
        # invalidate the element cache
        self._cache['network'] = None
        self._cache['hostmask'] = None
        self._cache['broadcast'] = None

    def subnet(self, prefixlen_diff=1):
        """The subnets which join to make the current subnet.

        In the case that self contains only one IP
        (self._prefixlen == 128), return a list with just ourself.

        Args:
            prefixlen_diff: An integer, the amount the prefix length
              should be increased by.

        Returns:
            A list of IPv6 objects.

        Raises:
            PrefixlenDiffInvalidError: The prefixlen_diff is too small
              or too large.

        """
        # Preserve original functionality (return [self] if
        # self.prefixlen == 128).
        if self._prefixlen == 128:
            return [self]

        if prefixlen_diff < 0:
            raise PrefixlenDiffInvalidError('Prefix length diff must be > 0')
        new_prefixlen = self._prefixlen + prefixlen_diff
        if not self._is_valid_netmask(str(new_prefixlen)):
            raise PrefixlenDiffInvalidError(
                'Prefix length diff %d is invalid for netblock %s' % (
                new_prefixlen, str(self)))
        first = IPv6('%s/%s' % (str(self.network),
                                str(self._prefixlen + prefixlen_diff)))
        subnets = [first]
        current = first
        while True:
            broadcast = current.broadcast
            if broadcast == self.broadcast:
                break
            current = IPv6('%s/%s' % (
                self._string_from_ip_int(int(broadcast) + 1),
                str(new_prefixlen)))
            subnets.append(current)

        return subnets

    def supernet(self, prefixlen_diff=1):
        """The supernet containing the current network.

        Args:
            prefixlen_diff: An integer, the amount the prefix length of the
              network should be decreased by.  For example, given a /96
              network and a prefixlen_diff of 3, a supernet with a /93
              netmask is returned.

        Returns:
            An IPv6 object.

        Raises:
            PrefixlenDiffInvalidError: If
              self._prefixlen - prefixlen_diff < 0. I.e., you have a
              negative prefix length.

        """
        if self._prefixlen == 0:
            return self
        if self._prefixlen - prefixlen_diff < 0:
            raise PrefixlenDiffInvalidError(
                'current prefixlen is %d, cannot have a prefixlen_diff of %d' %
                (self._prefixlen, prefixlen_diff))
        return IPv6('%s/%s' % (self._string_from_ip_int(self._ip),
                               str(self._prefixlen - prefixlen_diff)))

    @property
    def is_multicast(self):
        """Test if the address is reserved for multicast use.

        Returns:
            A boolean, True if the address is a multicast address.
            See RFC 2373 2.7 for details.

        """
        return self in IPv6('ff00::/8')

    @property
    def is_unspecified(self):
        """Test if the address is unspecified.

        Returns:
            A boolean, True if this is the unspecified address as defined in
            RFC 2373 2.5.2.

        """
        return self == IPv6('::')

    @property
    def is_loopback(self):
        """Test if the address is a loopback adddress.

        Returns:
            A boolean, True if the address is a loopback address as defined in
            RFC 2373 2.5.3.

        """
        return self == IPv6('::1')

    @property
    def is_link_local(self):
        """Test if the address is reserved for link-local.

        Returns:
            A boolean, True if the address is reserved per RFC 4291.

        """
        return self in IPv6('fe80::/10')

    @property
    def is_site_local(self):
        """Test if the address is reserved for site-local.

        Note that the site-local address space has been deprecated by RFC 3879.
        Use is_private to test if this address is in the space of unique local
        addresses as defined by RFC 4193.

        Returns:
            A boolean, True if the address is reserved per RFC 3513 2.5.6.

        """
        return self in IPv6('fec0::/10')

    @property
    def is_private(self):
        """Test if this address is allocated for private networks.

        Returns:
            A boolean, True if the address is reserved per RFC 4193.

        """
        return self in IPv6('fc00::/7')

    def _is_valid_netmask(self, prefixlen):
        """Verify that the netmask/prefixlen is valid.

        Args:
            prefixlen: A string, the netmask in prefix length format.

        Returns:
            A boolean, True if the prefix represents a valid IPv6
            netmask.

        """
        try:
            prefixlen = int(prefixlen)
        except ValueError:
            return False
        return 0 <= prefixlen <= 128

    # backwards compatibility
    Subnet = subnet
    Supernet = supernet


class IPv6(object):
    def __new__(cls, *args, **kwargs):
        if not args:
            return False
        if kwargs.has_key('host') and kwargs['host']:
            return IPv6Address(args[0])
        else:
            return IPv6Network(args[0])
