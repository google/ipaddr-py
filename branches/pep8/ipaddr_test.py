#!/usr/bin/python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unittest for ipaddr module."""


import unittest

import ipaddr


class IpaddrUnitTest(unittest.TestCase):

    def setUp(self):
        self.ipv4 = ipaddr.IPv4('1.2.3.4/24')
        self.ipv4_hostmask = ipaddr.IPv4('10.0.0.1/0.255.255.255')
        self.ipv6 = ipaddr.IPv6('2001:658:22a:cafe:200:0:0:1/64')

    def testRepr(self):
        self.assertEqual("IPv4('1.2.3.4/32')", repr(ipaddr.IPv4('1.2.3.4')))
        self.assertEqual("IPv6('::1/128')", repr(ipaddr.IPv6('::1')))

    def testInvalidStrings(self):
        self.assertRaises(ValueError, ipaddr.IP, '')
        self.assertRaises(ValueError, ipaddr.IP, 'www.google.com')
        self.assertRaises(ipaddr.IPv4IpValidationError, ipaddr.IPv4, '')
        self.assertRaises(ipaddr.IPv4IpValidationError, ipaddr.IPv4,
                          'google.com')
        self.assertRaises(ipaddr.IPv6IpValidationError, ipaddr.IPv6, '')
        self.assertRaises(ipaddr.IPv6IpValidationError, ipaddr.IPv6,
                          'google.com')

    def testGetNetwork(self):
        self.assertEqual(self.ipv4.network, 16909056)
        self.assertEqual(self.ipv4.network_ext, '1.2.3.0')
        self.assertEqual(self.ipv4_hostmask.network_ext, '10.0.0.0')

        self.assertEqual(self.ipv6.network,
                         42540616829182469433403647294022090752)
        self.assertEqual(self.ipv6.network_ext,
                         '2001:658:22a:cafe::')
        self.assertEqual(self.ipv6.hostmask_ext,
                         '::ffff:ffff:ffff:ffff')

    def testIpFromInt(self):
        self.assertEqual(self.ipv4.ip, ipaddr.IPv4(16909060).ip)
        self.assertRaises(ipaddr.IPv4IpValidationError,
                          ipaddr.IPv4, 2**32)
        self.assertRaises(ipaddr.IPv4IpValidationError,
                          ipaddr.IPv4, -1)

        self.assertEqual(self.ipv6.ip,
                         ipaddr.IPv6(42540616829182469433547762482097946625).ip)
        self.assertRaises(ipaddr.IPv6IpValidationError,
                          ipaddr.IPv6, 2**128)
        self.assertRaises(ipaddr.IPv6IpValidationError,
                          ipaddr.IPv6, -1)

        self.assertEqual(ipaddr.IP(self.ipv4.ip).version, 4)
        self.assertEqual(ipaddr.IP(self.ipv6.ip).version, 6)

    def testGetIp(self):
        self.assertEqual(self.ipv4.ip, 16909060)
        self.assertEqual(self.ipv4.ip_ext, '1.2.3.4')
        self.assertEqual(self.ipv4.ip_ext_full, '1.2.3.4')
        self.assertEqual(self.ipv4_hostmask.ip_ext, '10.0.0.1')

        self.assertEqual(self.ipv6.ip, 42540616829182469433547762482097946625)
        self.assertEqual(self.ipv6.ip_ext,
                         '2001:658:22a:cafe:200::1')
        self.assertEqual(self.ipv6.ip_ext_full,
                         '2001:0658:022a:cafe:0200:0000:0000:0001')

    def testGetNetmask(self):
        self.assertEqual(self.ipv4.netmask, 4294967040L)
        self.assertEqual(self.ipv4.netmask_ext, '255.255.255.0')
        self.assertEqual(self.ipv4_hostmask.netmask_ext, '255.0.0.0')
        self.assertEqual(self.ipv6.netmask,
                         340282366920938463444927863358058659840)
        self.assertEqual(self.ipv6.netmask_ext, 64)

    def testZeroNetmask(self):
        ipv4_zero_netmask = ipaddr.IPv4('1.2.3.4/0')
        self.assertEqual(ipv4_zero_netmask.netmask, 0)
        self.assert_(ipv4_zero_netmask._IsValidNetmask(str(0)))

        ipv6_zero_netmask = ipaddr.IPv6('::1/0')
        self.assertEqual(ipv6_zero_netmask.netmask, 0)
        self.assert_(ipv6_zero_netmask._IsValidNetmask(str(0)))

    def testGetBroadcast(self):
        self.assertEqual(self.ipv4.broadcast, 16909311L)
        self.assertEqual(self.ipv4.broadcast_ext, '1.2.3.255')

        self.assertEqual(self.ipv6.broadcast,
                         42540616829182469451850391367731642367)
        self.assertEqual(self.ipv6.broadcast_ext,
                         '2001:658:22a:cafe:ffff:ffff:ffff:ffff')

    def testGetPrefixlen(self):
        self.assertEqual(self.ipv4.prefixlen, 24)

        self.assertEqual(self.ipv6.prefixlen, 64)

    def testGetSupernet(self):
        self.assertEqual(self.ipv4.Supernet().prefixlen, 23)
        self.assertEqual(self.ipv4.Supernet().network_ext, '1.2.2.0')
        self.assertEqual(ipaddr.IPv4('0.0.0.0/0').Supernet(),
                         ipaddr.IPv4('0.0.0.0/0'))

        self.assertEqual(self.ipv6.Supernet().prefixlen, 63)
        self.assertEqual(self.ipv6.Supernet().network_ext,
                         '2001:658:22a:cafe::')
        self.assertEqual(ipaddr.IPv6('::0/0').Supernet(), ipaddr.IPv6('::0/0'))

    def testGetSupernet3(self):
        self.assertEqual(self.ipv4.Supernet(3).prefixlen, 21)
        self.assertEqual(self.ipv4.Supernet(3).network_ext, '1.2.0.0')

        self.assertEqual(self.ipv6.Supernet(3).prefixlen, 61)
        self.assertEqual(self.ipv6.Supernet(3).network_ext,
                         '2001:658:22a:caf8::')

    def testGetSubnet(self):
        self.assertEqual(self.ipv4.Subnet()[0].prefixlen, 25)
        self.assertEqual(self.ipv4.Subnet()[0].network_ext, '1.2.3.0')
        self.assertEqual(self.ipv4.Subnet()[1].network_ext, '1.2.3.128')

        self.assertEqual(self.ipv6.Subnet()[0].prefixlen, 65)

    def testGetSubnetForSingle32(self):
        ip = ipaddr.IPv4('1.2.3.4/32')
        subnets1 = [str(x) for x in ip.Subnet()]
        subnets2 = [str(x) for x in ip.Subnet(2)]
        self.assertEqual(subnets1, ['1.2.3.4/32'])
        self.assertEqual(subnets1, subnets2)

    def testGetSubnetForSingle128(self):
        ip = ipaddr.IPv6('::1/128')
        subnets1 = [str(x) for x in ip.Subnet()]
        subnets2 = [str(x) for x in ip.Subnet(2)]
        self.assertEqual(subnets1, ['::1/128'])
        self.assertEqual(subnets1, subnets2)

    def testSubnet2(self):
        ips = [str(x) for x in self.ipv4.Subnet(2)]
        self.assertEqual(
            ips,
            ['1.2.3.0/26', '1.2.3.64/26', '1.2.3.128/26', '1.2.3.192/26'])

        ipsv6 = [str(x) for x in self.ipv6.Subnet(2)]
        self.assertEqual(
            ipsv6,
            ['2001:658:22a:cafe::/66',
             '2001:658:22a:cafe:4000::/66',
             '2001:658:22a:cafe:8000::/66',
             '2001:658:22a:cafe:c000::/66'])

    def testSubnetFailsForLargeCidrDiff(self):
        self.assertRaises(ipaddr.PrefixlenDiffInvalidError, self.ipv4.Subnet, 9)
        self.assertRaises(ipaddr.PrefixlenDiffInvalidError, self.ipv6.Subnet,
                          65)

    def testSupernetFailsForLargeCidrDiff(self):
        self.assertRaises(ipaddr.PrefixlenDiffInvalidError, self.ipv4.Supernet,
                          25)
        self.assertRaises(ipaddr.PrefixlenDiffInvalidError, self.ipv6.Supernet,
                          65)

    def testSubnetFailsForNegativeCidrDiff(self):
        self.assertRaises(ipaddr.PrefixlenDiffInvalidError, self.ipv4.Subnet,
                          -1)
        self.assertRaises(ipaddr.PrefixlenDiffInvalidError, self.ipv6.Subnet,
                          -1)

    def testGetNumHosts(self):
        self.assertEqual(self.ipv4.numhosts, 256)
        self.assertEqual(self.ipv4.Subnet()[0].numhosts, 128)
        self.assertEqual(self.ipv4.Supernet().numhosts, 512)

        self.assertEqual(self.ipv6.numhosts, 18446744073709551616)
        self.assertEqual(self.ipv6.Subnet()[0].numhosts, 9223372036854775808)
        self.assertEqual(self.ipv6.Supernet().numhosts, 36893488147419103232)

    def testContains(self):
        self.assertTrue(self.ipv4.Contains(ipaddr.IPv4('1.2.3.128/25')))
        self.assertTrue(ipaddr.IPv4('1.2.3.128/25') in self.ipv4)
        self.assertFalse(self.ipv4.Contains(ipaddr.IPv4('1.2.4.1/24')))
        self.assertFalse(ipaddr.IPv4('1.2.4.1/24') in self.ipv4)
        self.assertFalse(self.ipv4 in self.ipv6)
        self.assertFalse(self.ipv6 in self.ipv4)
        self.assertTrue(self.ipv4 in self.ipv4)
        self.assertTrue(self.ipv6 in self.ipv6)

    def testBadAddress(self):
        self.assertRaises(ipaddr.IPv4IpValidationError, ipaddr.IPv4, 'poop')
        self.assertRaises(ipaddr.IPv4IpValidationError,
                          ipaddr.IPv4, '1.2.3.256')

        self.assertRaises(ipaddr.IPv6IpValidationError, ipaddr.IPv6, 'poopv6')
        self.assertRaises(ipaddr.IPv4IpValidationError,
                          ipaddr.IPv4, '1.2.3.4/32/24')

    def testBadNetMask(self):
        self.assertRaises(ipaddr.IPv4NetmaskValidationError,
                          ipaddr.IPv4, '1.2.3.4/')
        self.assertRaises(ipaddr.IPv4NetmaskValidationError,
                          ipaddr.IPv4, '1.2.3.4/33')
        self.assertRaises(ipaddr.IPv4NetmaskValidationError,
                          ipaddr.IPv4, '1.2.3.4/254.254.255.256')

        self.assertRaises(ipaddr.IPv6NetmaskValidationError,
                          ipaddr.IPv6, '::1/')
        self.assertRaises(ipaddr.IPv6NetmaskValidationError,
                          ipaddr.IPv6, '::1/129')

    def testNth(self):
        self.assertEqual(self.ipv4[5], '1.2.3.5')
        self.assertRaises(IndexError, self.ipv4.__getitem__, 256)

        self.assertEqual(self.ipv6[5],
                         '2001:658:22a:cafe::5')

    def testEquals(self):
        self.assertTrue(self.ipv4.__eq__(ipaddr.IPv4('1.2.3.4/24')))
        self.assertFalse(self.ipv4.__eq__(ipaddr.IPv4('1.2.3.4/23')))
        self.assertFalse(self.ipv4.__eq__(ipaddr.IPv4('1.2.3.5/24')))

        self.assertTrue(self.ipv6.__eq__(
            ipaddr.IPv6('2001:658:22a:cafe:200::1/64')))
        self.assertFalse(self.ipv6.__eq__(
            ipaddr.IPv6('2001:658:22a:cafe:200::1/63')))
        self.assertFalse(self.ipv6.__eq__(
            ipaddr.IPv6('2001:658:22a:cafe:200::2/64')))

    def testSlash32Constructor(self):
        self.assertEquals(str(ipaddr.IPv4('1.2.3.4/255.255.255.255')),
                          '1.2.3.4/32')

    def testSlash128Constructor(self):
        self.assertEquals(str(ipaddr.IPv6('::1/128')),
                                  '::1/128')

    def testSlash0Constructor(self):
        self.assertEquals(str(ipaddr.IPv4('1.2.3.4/0.0.0.0')), '1.2.3.4/0')

    def testCollapsing(self):
        ip1 = ipaddr.IPv4('1.1.0.0/24')
        ip2 = ipaddr.IPv4('1.1.1.0/24')
        ip3 = ipaddr.IPv4('1.1.2.0/24')
        ip4 = ipaddr.IPv4('1.1.3.0/24')
        ip5 = ipaddr.IPv4('1.1.4.0/24')
        # stored in no particular order b/c we want CollapseAddr to call [].sort
        # and we want that sort to call ipaddr.IP.__cmp__() on our array members
        ip6 = ipaddr.IPv4('1.1.0.0/22')
        # check that addreses are subsumed properlly.
        collapsed = ipaddr.CollapseAddrList([ip1, ip2, ip3, ip4, ip5, ip6])
        self.assertEqual(collapsed, [ipaddr.IPv4('1.1.0.0/22'),
                                     ipaddr.IPv4('1.1.4.0/24')])
        # test that two addresses are supernet'ed properlly
        collapsed = ipaddr.CollapseAddrList([ip1, ip2])
        self.assertEqual(collapsed, [ipaddr.IPv4('1.1.0.0/23')])

        ip_same1 = ip_same2 = ipaddr.IPv4('1.1.1.1/32')
        self.assertEqual(ipaddr.CollapseAddrList([ip_same1, ip_same2]),
                         [ip_same1])
        ip1 = ipaddr.IPv6('::2001:1/100')
        ip2 = ipaddr.IPv6('::2002:1/120')
        ip3 = ipaddr.IPv6('::2001:1/96')
        # test that ipv6 addresses are subsumed properlly.
        collapsed = ipaddr.CollapseAddrList([ip1, ip2, ip3])
        self.assertEqual(collapsed, [ip3])

    def testNetworkComparison(self):
        # ip1 and ip2 have the same network address
        ip1 = ipaddr.IPv4('1.1.1.0/24')
        ip2 = ipaddr.IPv4('1.1.1.1/24')
        ip3 = ipaddr.IPv4('1.1.2.0/24')

        self.assertEquals(ip1.__cmp__(ip3), -1)
        self.assertEquals(ip3.__cmp__(ip2), 1)

        self.assertEquals(ip1.CompareNetworks(ip2), 0)

        ip1 = ipaddr.IPv6('2001::2000/96')
        ip2 = ipaddr.IPv6('2001::2001/96')
        ip3 = ipaddr.IPv6('2001:ffff::2000/96')

        self.assertEquals(ip1.__cmp__(ip3), -1)
        self.assertEquals(ip3.__cmp__(ip2), 1)
        self.assertEquals(ip1.CompareNetworks(ip2), 0)

        # Test comparing different protocols
        ipv6 = ipaddr.IPv6('::/0')
        ipv4 = ipaddr.IPv4('0.0.0.0/0')
        self.assertEquals(ipv6.__cmp__(ipv4), 1)
        self.assertEquals(ipv4.__cmp__(ipv6), -1)

    def testEmbeddedIpv4(self):
        ipv4_string = '192.168.0.1'
        ipv4 = ipaddr.IPv4(ipv4_string)
        v4compat_ipv6 = ipaddr.IPv6('::%s' % ipv4_string)
        self.assertEquals(v4compat_ipv6.ip, ipv4.ip)
        v4mapped_ipv6 = ipaddr.IPv6('::ffff:%s' % ipv4_string)
        self.assertNotEquals(v4mapped_ipv6.ip, ipv4.ip)
        self.assertRaises(ipaddr.IPv6IpValidationError, ipaddr.IPv6,
                          '2001:1.1.1.1:1.1.1.1')

    def testIPVersion(self):
        self.assertEqual(self.ipv4.version, 4)
        self.assertEqual(self.ipv6.version, 6)

    def testIpStrFromPrefixlen(self):
        ipv4 = ipaddr.IPv4('1.2.3.4/24')
        self.assertEquals(ipv4._IpStrFromPrefixlen(), '255.255.255.0')
        self.assertEquals(ipv4._IpStrFromPrefixlen(28), '255.255.255.240')

    def testIpType(self):
        ipv4 = ipaddr.IP('1.2.3.4')
        ipv6 = ipaddr.IP('::1.2.3.4')
        self.assertEquals(ipaddr.IPv4, type(ipv4))
        self.assertEquals(ipaddr.IPv6, type(ipv6))

    def testReserved(self):
        self.assertEquals(True, ipaddr.IP('224.1.1.1/31').IsMulticast())
        self.assertEquals(True, ipaddr.IP('192.168.1.1/17').IsRFC1918())
        self.assertEquals(True, ipaddr.IP('169.254.100.200/24').IsLinkLocal())
        self.assertEquals(True, ipaddr.IP('127.100.200.254/32').IsLoopback())

    def testAddrExclude(self):
        addr1 = ipaddr.IP('10.1.1.0/24')
        addr2 = ipaddr.IP('10.1.1.0/26')
        addr3 = ipaddr.IP('10.2.1.0/24')
        self.assertEqual(addr1.AddressExclude(addr2),
                         [ipaddr.IP('10.1.1.64/26'),
                          ipaddr.IP('10.1.1.128/25')])
        self.assertRaises(ValueError, addr1.AddressExclude, addr3)

    def testHash(self):
        self.assertEquals(hash(ipaddr.IP('10.1.1.0/24')),
                          hash(ipaddr.IP('10.1.1.0/24')))
        dummy = {}
        dummy[self.ipv4] = None
        dummy[self.ipv6] = None
        self.assertTrue(dummy.has_key(self.ipv4))

    def testIPv4PrefixFromInt(self):
        addr1 = ipaddr.IP('10.1.1.0/24')
        addr2 = ipaddr.IPv4(addr1.ip)  # clone prefix
        addr2.SetPrefix(addr1.prefixlen)
        addr3 = ipaddr.IP(123456)

        self.assertEqual(123456, addr3.ip)
        self.assertRaises(ipaddr.IPv4NetmaskValidationError,
                          addr2.SetPrefix, -1L)
        self.assertEqual(addr1, addr2)
        self.assertEqual(str(addr1), str(addr2))

    def testIPv6PrefixFromInt(self):
        addr1 = ipaddr.IP('2001:0658:022a:cafe:0200::1/64')
        addr2 = ipaddr.IPv6(addr1.ip)  # clone prefix
        addr2.SetPrefix(addr1.prefixlen)
        addr3 = ipaddr.IP(123456)

        self.assertEqual(123456, addr3.ip)
        self.assertRaises(ipaddr.IPv6NetmaskValidationError,
                          addr2.SetPrefix, -1L)
        self.assertEqual(addr1, addr2)
        self.assertEqual(str(addr1), str(addr2))

    def testCopyConstructor(self):
        addr1 = ipaddr.IP('10.1.1.0/24')
        addr2 = ipaddr.IP(addr1)
        addr3 = ipaddr.IP('2001:658:22a:cafe:200::1/64')
        addr4 = ipaddr.IP(addr3)

        self.assertEqual(addr1, addr2)
        self.assertEqual(addr3, addr4)

    def testCompressIPv6Address(self):
        test_addresses = {
            '1:2:3:4:5:6:7:8': '1:2:3:4:5:6:7:8/128',
            '2001:0:0:4:0:0:0:8': '2001:0:0:4::8/128',
            '2001:0:0:4:5:6:7:8': '2001::4:5:6:7:8/128',
            '2001:0:3:4:5:6:7:8': '2001:0:3:4:5:6:7:8/128',
            '2001:0::3:4:5:6:7:8': '2001:0:3:4:5:6:7:8/128',
            '0:0:3:0:0:0:0:ffff': '0:0:3::ffff/128',
            '0:0:0:4:0:0:0:ffff': '::4:0:0:0:ffff/128',
            '0:0:0:0:5:0:0:ffff': '::5:0:0:ffff/128',
            '1:0:0:4:0:0:7:8': '1::4:0:0:7:8/128',
            '0:0:0:0:0:0:0:0': '::/128',
            '0:0:0:0:0:0:0:0/0': '::/0',
            '0:0:0:0:0:0:0:1': '::1/128',
            '2001:0658:022a:cafe:0000:0000:0000:0000/66':
            '2001:658:22a:cafe::/66',
            }
        for uncompressed, compressed in test_addresses.items():
            self.assertEquals(compressed, str(ipaddr.IPv6(uncompressed)))

    def testExplodeShortHandIpStr(self):
        addr1 = ipaddr.IPv6('2001::1')
        self.assertEqual('2001:0000:0000:0000:0000:0000:0000:0001',
                         addr1._ExplodeShortHandIpStr(addr1.ip_ext))

    def testIntRepresentation(self):
        self.assertEqual(16909060, int(self.ipv4))
        self.assertEqual(42540616829182469433547762482097946625, int(self.ipv6))

    def testHexRepresentation(self):
        self.assertEqual('0x1020304', hex(self.ipv4))

        # Force the return value to uppercase to workaround Python version
        # differences, i.e.:
        #   2.4.3: hex(long(10)) == '0xAL'
        #   2.5.1: hex(long(10)) == '0xaL'
        self.assertEqual('0X20010658022ACAFE0200000000000001L',
                         hex(self.ipv6).upper())


if __name__ == '__main__':
    unittest.main()
