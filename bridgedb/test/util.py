# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2007-2017, The Tor Project, Inc.
#             (c) 2007-2017, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittest utilities."""

from __future__ import print_function
from __future__ import unicode_literals

import errno
import ipaddr
import os
import random
import time

from functools import wraps

from twisted.trial import unittest

from bridgedb import util as bdbutil
from bridgedb.bridges import IBridge
from bridgedb.parse.addr import isIPAddress

from zope.interface import implementer


def fileCheckDecorator(func):
    """Method decorator for a t.t.unittest.TestCase test_* method.

    .. codeblock:: python

        import shutil
        from twisted.trial import unittest

        pyunit = __import__('unittest')

        class TestTests(unittest.TestCase):
            @fileCheckDecorator
            def doCopyFile(src, dst, description=None):
                shutil.copy(src, dst)
            def test_doCopyFile(self):
                srcfile = self.mktemp()
                dstfile = self.mktemp()
                with open(srcfile, 'wb') as fh:
                    fh.write('testing TestCase method decorator utility')
                    fh.flush()
                self.doCopyFile(srcfile, dstfile, 'asparagus')

        testtest = TestTests()
        testtest.runTest()

    ..

    :type func: callable
    :param func: The ``test_*`` method, from a
                 :api:`twisted.trial.unittest.TestCase` instance, to wrap.
    """
    @wraps(func)
    def wrapper(self, src, dst, description):
        self.assertTrue(os.path.isfile(src),
                        "Couldn't find original %s file: %r"
                        % (str(description), src))
        func(self, src, dst, description)
        self.assertTrue(os.path.isfile(dst),
                        "Couldn't find new %s file: %r. Original: %r"
                        % (str(description), dst, src))
    return wrapper

def processExists(pid):
    """Test if the process with **pid** exists.

    :param int pid: An integer specifying the process ID.
    :raises: OSError, if ``OSError.errno`` wasn't an expected errno (according
        to the "ERRORS" section from ``man 2 kill``).
    :rtype: bool
    :returns: ``True`` if a process with **pid** exists, ``False`` otherwise.
    """
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:  # ESRCH: No such process
            return False
        if err.errno == errno.EPERM:  # EPERM: Operation not permitted
            # If we're not allowed to signal the process, then there exists a
            # process that we don't have permissions to access.
            return True
        else:
            raise
    else:
        return True

def getBridgeDBPID(pidfile="bridgedb.pid"):
    """Read the ``bridgedb.pid`` file in **rundir**, if it exists, to get the
    PID.

    :param str pidfile: The path to the BridgeDB pidfile.
    :rtype: int
    :returns: The process ID, if available, otherwise ``0``.
    """
    fh = None
    try:
        fh = open(pidfile)
    except (IOError, OSError) as err:
        print(err)
        pid = 0
    else:
        pid = int(fh.read())

    if fh:
        fh.close()

    return pid

def bracketIPv6(ip):
    """Put brackets around an IPv6 address, just as tor does."""
    return "[%s]" % ip

def randomPort():
    return random.randint(1, 65535)

def randomHighPort():
    return random.randint(1024, 65535)

def randomIPv4():
    return ipaddr.IPv4Address(random.getrandbits(32))

def randomIPv6():
    return ipaddr.IPv6Address(random.getrandbits(128))

def randomIP():
    if random.choice(range(2)):
        return randomIPv4()
    return randomIPv6()

def randomIPv4String():
    return randomIPv4().compressed

def randomIPv6String():
    return bracketIPv6(randomIPv6().compressed)

def randomIPString():
    if random.choice(range(2)):
        return randomIPv4String()
    return randomIPv6String()

def valid(func):
    """Wrapper for the above ``randomIPv*`` functions to ensure they only
    return addresses which BridgeDB considers "valid".

    .. seealso:: :func:`bridgedb.parse.addr.isIPAddress`
    """
    @wraps(func)
    def wrapper():
        ip = None
        while not isIPAddress(ip):
            ip = func()
        return ip
    return wrapper

randomValidIPv4       = valid(randomIPv4)
randomValidIPv6       = valid(randomIPv6)
randomValidIP         = valid(randomIP)
randomValidIPv4String = valid(randomIPv4String)
randomValidIPv6String = valid(randomIPv6String)
randomValidIPString   = valid(randomIPString)

_FAKE_BRIDGES = []

def generateFakeBridges(n=500):
    """Generate a set of **n** :class:`~bridgedb.bridges.Bridge`s with random
    data.
    """
    from bridgedb.bridges import Bridge
    from bridgedb.bridges import PluggableTransport

    global _FAKE_BRIDGES

    if _FAKE_BRIDGES:
        return _FAKE_BRIDGES

    bridges = []

    for i in range(n):
        addr = randomValidIPv4String()
        nick = 'bridge-%d' % i
        port = randomHighPort()
        # Real tor currently only supports one extra ORAddress, and it can
        # only be IPv6.
        addrs = [(randomValidIPv6(), randomHighPort(), 6)]
        fpr = "".join(random.choice('abcdef0123456789') for _ in range(40))

        supported = ["obfs2", "obfs3", "fte"]
        transports = []
        for j, method in zip(range(1, len(supported) + 1), supported):
            pt = PluggableTransport(fpr, method, addr, port - j, {})
            transports.append(pt)

        # Every tenth bridge supports obfs4.
        if i % 10 == 0:
            obfs4Args = {'iat-mode': '1',
                         'node-id': '2a79f14120945873482b7823caabe2fcde848722',
                         'public-key': '0a5b046d07f6f971b7776de682f57c5b9cdc8fa060db7ef59de82e721c8098f4'}
            pt = PluggableTransport(fpr, "obfs4", addr, port - j,
                                    obfs4Args)
            transports.append(pt)

        # Every fifteenth bridge supports scramblesuit.
        if i % 15 == 0:
            scramblesuitArgs = {'password': 'NEQGQYLUMUQGK5TFOJ4XI2DJNZTS4LRO'}
            pt = PluggableTransport(fpr, "scramblesuit", addr, port - j,
                                    scramblesuitArgs)
            transports.append(pt)

        bridge = Bridge(nick, addr, port, fpr)
        bridge.flags.update("Running Stable")
        bridge.transports = transports
        bridge.orAddresses = addrs
        bridges.append(bridge)

    _FAKE_BRIDGES = bridges
    return bridges


#: Mixin class for use with :api:`~twisted.trial.unittest.TestCase`. A
#: ``TestCaseMixin`` can be used to add additional methods, which should be
#: common to multiple ``TestCase`` subclasses, without the ``TestCaseMixin``
#: being run as a ``TestCase`` by ``twisted.trial``.
TestCaseMixin = bdbutil.mixin
TestCaseMixin.register(unittest.TestCase)


class Benchmarker(object):
    """Wrap a context with a timer to benchmark execution time.

    .. hint:: Use like so::

            with Benchmarker():
                 foo(bar, baz)

        Once the ``with`` context exits, something like::

            Benchmark: 180.269957ms (0s)

        will be printed to stdout (if **verbose** is set to ``True``).
    """

    def __init__(self, verbose=True):
        self.verbose = verbose

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.seconds = self.end - self.start
        self.milliseconds = self.seconds * 1000
        if self.verbose:
            print("Benchmark: %12fms %12fs" % (self.milliseconds, self.seconds))


@implementer(IBridge)
class DummyBridge(object):
    """A mock :class:`bridgedb.bridges.Bridge` which only supports a mocked
    ``getBridgeLine`` method."""

    ptArgs = {}

    def __init__(self):
        """Create a mocked bridge suitable for testing distributors and web
        resource rendering.
        """
        ipv4 = randomIPv4()
        self.nickname = "bridge-{0}".format(ipv4)
        self.address = ipaddr.IPv4Address(ipv4)
        self.orPort = randomPort()
        self.fingerprint = "".join(random.choice('abcdef0123456789')
                                   for _ in range(40))
        self.orAddresses = [(randomIPv6(), randomPort(), 6)]

    def getBridgeLine(self, bridgeRequest, includeFingerprint=True):
        """Get a "torrc" bridge config line to give to a client."""
        if not bridgeRequest.isValid():
            return
        line = []
        if bridgeRequest.transports:
            line.append(bridgeRequest.transports[-1])  # Just the last PT
        if bridgeRequest.ipVersion is 6:
            line.append("[%s]:%s" % self.orAddresses[0][:2])
        else:
            line.append("%s:%s" % (self.address, self.orPort))
        if includeFingerprint is True:
            line.append(self.fingerprint)
        if self.ptArgs:
            line.append(','.join(['='.join(x) for x in self.ptArgs.items()]))
        return " ".join([item for item in line])


@implementer(IBridge)
class DummyMaliciousBridge(DummyBridge):
    """A mock :class:`bridgedb.bridges.Bridge` which only supports a mocked
    ``getConfigLine`` method and which maliciously insert an additional fake
    bridgeline and some javascript into its PT arguments.
    """
    ptArgs = {
        "eww": "\rBridge 1.2.3.4:1234",
        "bad": "\nBridge 6.6.6.6:6666 0123456789abcdef0123456789abcdef01234567",
        "evil": "<script>alert('fuuuu');</script>",
    }
