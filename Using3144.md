# Information and examples on using ipaddr from branches/3144

# Using ipaddr #

What follows is an introducion to using ipaddr-py. These exmples use the version from branches/3144.

## Creating Address/Network/Interface objects ##

> Since ipaddr-py is library for inspecting and manipulating IP address, the first thing you'll want to do is create some objects. You can use ipaddr to create objects from strings, integers or other ipaddr objects.

  * Creating Addresses.

> Addresses are the most basic unit. They are indivisable.

> IPv4 Address:

```
  # string constructor.
  >>> ipaddr.IPv4Address('192.0.2.1')
  IPv4Address('192.0.2.1')

  # integer constructor.
  >>> ipaddr.IPv4Address(3221225985)
  IPv4Address('192.0.2.1')

  # copy constructor.
  >>> addr = ipaddr.IPv4Address('192.0.2.1')
  >>> ipaddr.IPv4Address(addr)
  IPv4Address('192.0.2.1')
```

> IPv6 Address:

```
  # string constructor.
  >>> ipaddr.IPv6Address('2001:DB8::1')
  IPv6Address('2001:db8::1')

  # integer constructor - this one's a mouthful.
  >>> ipaddr.IPv6Address(42540766411282592856903984951653826561L)
  IPv6Address('2001:db8::1')

  # copy constructor
  >>> ipaddr.IPv6Address(addr)
  IPv6Address('2001:db8::1')
```

  * Creating Networks.

> Addresses are usually grouped together in Networks, so ipaddr provides a way to create, inspect and maniuplate those as well. The constructors look identical to their corresponding address constructor.

> IPv4 Network:
```
  >>> ipaddr.IPv4Network('192.0.2.0/24')
  IPv4Network('192.0.2.0/24')
  >>> ipaddr.IPv4Network(3221225984)
  IPv4Network('192.0.2.0/32')
  >>> addr = ipaddr.IPv4Network('192.0.2.0/24')
  >>> ipaddr.IPv4Network(addr)
  IPv4Network('192.0.2.0/24')
```

> IPv6 Network:
```
  >>> ipaddr.IPv6Network('2001:db8::0/96')
  IPv6Network('2001:db8::/96')
  >>> ipaddr.IPv6Network(42540766411282592856903984951653826560L)
  IPv6Network('2001:db8::/128')
  >>> addr = ipaddr.IPv6Network('2001:db8::0/96')
  >>> ipaddr.IPv6Network(addr)
  IPv6Network('2001:db8::/96')
```

> Network objects cannot have any host bits set. The practical effect of this is that, '192.0.2.1/24' does not describe a network. It's referred to as an interface object since the ip-on-a-network notation is commonly used to describe network interfaces of a computer on a given network.

Note: when creating a network object from an integer, the prefix length
(netmask) is assumed to be all ones. So IPv4 networks will have a /32 netmask
and IPv6 networks will have a /128 netmask.

  * Creating hybrid objects.

> As mentioned just above, if you need to describe an address on a particular network, neither the address nor the network classes is appropriate. Since the notation 192.0.2.1/24 is so common among network engineers and the people who write tools for firewalls and routers, ipaddr provides a set of hybrid classes. By now, the constructor syntax should look familair.

> IPv4Interface:
```
  >>> ipaddr.IPv4Interface('192.0.2.1/24')
  IPv4Interface('192.0.2.1/24')
  >>> ipaddr.IPv4Interface(3221225985)
  IPv4Interface('192.0.2.1/32')
  >>> addr = ipaddr.IPv4Interface('192.0.2.1/24')
  >>> ipaddr.IPv4Interface(addr)
  IPv4Interface('192.0.2.1/24')
```

> IPv6Interface:
```
  >>> ipaddr.IPv6Interface('2001:db8::1/96')
  IPv6Interface('2001:db8::1/96')
  >>> ipaddr.IPv6Interface(42540766411282592856903984951653826561L)
  IPv6Interface('2001:db8::1/128')
  >>> addr = ipaddr.IPv6Interface('2001:db8::1/96')
  >>> ipaddr.IPv6Interface(addr)
  IPv6Interface('2001:db8::1/96')
```

Note: Just like with the network objects, when you create an interface object with an integer, the netmask is assumed to be all ones.

> Finally, if you don't know at the time coding what type of addresses you might be handling, or you don't really care and you'd like the same code to handle both, ipaddr provides generic factory functions which look at the address and try to return an object of the correct for you.

  * Addresses
```
  >>> ipaddr.ip_address('192.0.2.1')
  IPv4Address('192.0.2.1')
  >>> ipaddr.ip_address('2001:db8::1')
  IPv6Address('2001:db8::1')
  >>> ipaddr.ip_address(1)
  IPv4Address('0.0.0.1')
  >>> addr = ipaddr.ip_address('2001:db8::1')
  >>> ipaddr.ip_address(addr)
  IPv6Address('2001:db8::1')
```

  * Networks
```
  >>> ipaddr.ip_network('192.0.2.0/24')
  IPv4Network('192.0.2.0/24')
  >>> addr = ipaddr.ip_network('192.0.2.0/24')
  >>> ipaddr.ip_network(addr)
  IPv4Network('192.0.2.0/24')
  >>> ipaddr.ip_network('2001:db8::0/96')
  IPv6Network('2001:db8::/96')
```

  * Interfaces
```
  >>> ipaddr.ip_interface('192.0.2.1/24')
  IPv4Interface('192.0.2.1/24')
  >>> ipaddr.ip_interface('2001:db8::1/96')
  IPv6Interface('2001:db8::1/96')
```

Note: Since IPv4 addresses are 2<sup>32</sup> bits and IPv6 addresses are 2<sup>128</sup> bits, all integers <= 2<sup>32</sup> - 1 are assumed to be IPv4. If you know that an address is an IPv6 address, you should pass version=6 to ip\_address().

  * explicit versioning
```
  >>> ipaddr.ip_address(3221225985)
  IPv4Address('192.0.2.1')
  >>> ipaddr.ip_address(3221225985, version=6)
  IPv6Address('::c000:201')
```

## Inspecting Address/Network/Interface Objects ##

> You've gone to the trouble of creating an IPv(4|6)(Address|Network|Interface) object, so you probably want to get information about it. ipaddr tries to make doing this easy and intuitive.

  * IP version.
```
  >>> addr4 = ipaddr.ip_address('192.0.2.1')
  >>> addr6 = ipaddr.ip_address('2001:db8::1')
  >>> addr6.version
  6
  >>> addr4.version
  4
```

  * Network/Interface
```
  >>> net4 = ipaddr.ip_network('192.0.2.0/24')
  >>> net6 = ipaddr.ip_network('2001:db8::0/96')
```

  * finding out how many individual addresses are in a network.
```
  >>> net4.numhosts
  256
  >>> net6.numhosts
  4294967296L
```

  * iterating through the 'usable' addresses on a network.
```
  >>> for x in net4.iterhosts():
        print x
  192.0.2.1
  192.0.2.2
  192.0.2.3
  192.0.2.4
  [snip]
  192.0.2.252
  192.0.2.253
  192.0.2.254
```

  * host/netmask
```
  >>> net6.netmask
  IPv6Address('ffff:ffff:ffff:ffff:ffff:ffff::')
  >>> net6.hostmask
  IPv6Address('::ffff:ffff')
```

  * Exploding or compressing the address
```
  >>> net6.exploded
  '2001:0000:0000:0000:0000:0000:0000:0000/96'
  >>> addr6.exploded
  '2001:0000:0000:0000:0000:0000:0000:0001'
```

## Networks/Interfaces as lists ##

> It's sometimes useful to treat networks (and interfaces) as lists. This allows us to index them like this:

```
  >>> net6[1]
  IPv6Address('2001::1')
  >>> net6[-1]
  IPv6Address('2001::ffff:ffff')
  >>> ipaddr.ip_interface('192.0.2.1/24')[-1]
  IPv4Address('192.0.2.255')
```

This also means that network and interface objects lend themselves to using the list membership test syntax ` in ` like this:

```
  if address in network:
    # do something
```

> Address, Network and Interface objects can be 'in' a network or an interface object.

```
  >>> net4 = ipaddr.ip_network('192.0.2.0/25')
  >>> net4 in ipaddr.ip_network('192.0.2.0/24')
  True
  >>> net4 in ipaddr.ip_interface('192.0.2.0/25')
  True
  net4 in ipaddr.ip_interface('192.0.2.0/26')
```

## Comparisons ##

> ipaddr provides some simply, hopefully intuitive ways to compare objects, where it makes sense.

```
  >>> ipaddr.ip_address('192.0.2.1') < ipaddr.ip_address('192.0.2.2')
  True
```

> A TypeError exception is raised if you try to compare objects of different versions or different types.

## Exceptions raised by ipaddr ##

> If you try to create an address/network/interface object with an invalid value for either the address or netmask, ipaddr will raise an AddressValueError or NetmaskValueError respectively. Both of these exceptions have ValueError as their parent class, so if you're not concerned with the particular type of error, you can do the following:

```
  try:
    ipaddr.ip_address(address)
  except ValueError:
    print 'address/netmask is invalid: %s' % address
```