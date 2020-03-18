# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2017, Isis Lovecruft
#             (c) 2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.Bridges`."""

from __future__ import print_function

import copy
import io
import ipaddr
import logging
import tempfile
import os

from twisted.trial import unittest

import bridgedb.Storage

from bridgedb import Bridges
from bridgedb import crypto
from bridgedb.test import util
from bridgedb.distributors.https.distributor import HTTPSDistributor
from bridgedb.distributors.moat.distributor import MoatDistributor

# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#Bridges.logging.getLogger().setLevel(10)


class BridgeRingTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.Bridges.BridgeRing`."""

    def setUp(self):
        self.ring = Bridges.BridgeRing('fake-hmac-key')

    def addRandomBridges(self):
        bridges = copy.deepcopy(util.generateFakeBridges())

        [self.ring.insert(bridge) for bridge in bridges]

    def addBridgesFromSameSubnet(self):
        bridges = copy.deepcopy(util.generateFakeBridges())
        subnet = "5.5.%d.%d"
        i = 1
        j = 1

        for bridge in bridges:
            bridge.address = ipaddr.IPAddress(subnet % (i, j))
            self.ring.insert(bridge)

            if j == 255:
                j  = 1
                i += 1
            else:
                j += 1

    def test_filterDistinctSubnets(self):
        """If there are bridges in the same subnet then they should be
        filtered out of the results.
        """
        self.addBridgesFromSameSubnet()

        chosen = list(self.ring.bridges.keys())[:10]
        bridges = self.ring.filterDistinctSubnets(chosen)

        # Since they're all in the same /16, we should only get one
        # bridge back:
        self.assertEqual(len(bridges), 1)

    def test_filterDistinctSubnets_random_bridges(self):
        """Even after filtering, in a normal case we should get the amount of
        bridges we asked for.  However, we should always get at least one.
        """
        self.addRandomBridges()

        chosen = list(self.ring.bridges.keys())[:3]
        bridges = self.ring.filterDistinctSubnets(chosen)

        self.assertGreaterEqual(len(bridges), 1)

    def test_clear(self):
        """Clear should get rid of all the inserted bridges."""
        self.addRandomBridges()
        self.assertGreater(len(self.ring), 0)
        self.ring.clear()
        self.assertEqual(len(self.ring), 0)

    def test_getBridges_filterBySubnet(self):
        """We should still get the number of bridges we asked for, even when
        filtering by distinct subnets.
        """
        self.addRandomBridges()
        bridges = self.ring.getBridges(b'a' * Bridges.DIGEST_LEN, N=3, filterBySubnet=True)
        self.assertEqual(len(bridges), 3)

    def test_dumpAssignments(self):
        """This should dump the bridges to the file."""
        self.addRandomBridges()

        f = io.StringIO()

        self.ring.dumpAssignments(f)

        f.flush()
        f.seek(0)

        data = f.read()
        first = list(self.ring.bridges.values())[0].fingerprint

        # The first bridge's fingerprint should be within the data somewhere
        self.assertIn(first, data)


class FixedBridgeSplitterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.Bridges.FixedBridgeSplitter`."""

    def setUp(self):
        self.rings = [Bridges.BridgeRing('fake-hmac-key-1'),
                      Bridges.BridgeRing('fake-hmac-key-2')]
        self.splitter = Bridges.FixedBridgeSplitter('fake-hmac-key', self.rings)

    def addRandomBridges(self):
        bridges = copy.deepcopy(util.generateFakeBridges())

        [self.splitter.insert(bridge) for bridge in bridges]

    def test_insert(self):
        self.addRandomBridges()
        self.assertGreater(len(self.splitter), 0)

    def test_clear(self):
        """Clear should get rid of all the inserted bridges."""
        self.addRandomBridges()
        self.assertGreater(len(self.splitter), 0)
        self.splitter.clear()
        self.assertEqual(len(self.splitter), 0)

    def test_dumpAssignments(self):
        """This should dump the bridges to the file."""
        self.addRandomBridges()

        f = io.StringIO()

        self.splitter.dumpAssignments(f)

        f.flush()
        f.seek(0)

        data = f.read()
        first = list(self.splitter.rings[0].bridges.values())[0].fingerprint

        # The first bridge's fingerprint should be within the data somewhere
        self.assertIn(first, data)


class BridgeSplitterTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.Bridges.BridgeSplitter`."""

    def setUp(self):

        self.bridges = copy.deepcopy(util.generateFakeBridges())

        self.fd, self.fname = tempfile.mkstemp(suffix=".sqlite", dir=os.getcwd())
        bridgedb.Storage.initializeDBLock()
        self.db = bridgedb.Storage.openDatabase(self.fname)
        bridgedb.Storage.setDBFilename(self.fname)

        key = 'fake-hmac-key'
        self.splitter = Bridges.BridgeSplitter(key)
        ringParams = Bridges.BridgeRingParameters(needPorts=[(443, 1)],
                                                  needFlags=[("Stable", 1)])
        self.https_distributor = HTTPSDistributor(
            4,
            crypto.getHMAC(key, "HTTPS-IP-Dist-Key"),
            None,
            answerParameters=ringParams)
        self.moat_distributor = MoatDistributor(
            4,
            crypto.getHMAC(key, "Moat-Dist-Key"),
            None,
            answerParameters=ringParams)

        self.splitter.addRing(self.https_distributor.hashring, "https", p=10)
        self.splitter.addRing(self.moat_distributor.hashring, "moat", p=10)
        self.https_ring = self.splitter.ringsByName.get("https")
        self.moat_ring = self.splitter.ringsByName.get("moat")

    def tearDown(self):
        self.db.close()
        os.close(self.fd)
        os.unlink(self.fname)

    def test_insert(self):
        bridge = self.bridges[0]

        # Assume a bridge wants to be distribute over HTTPS.
        bridge.distribution_request = "https"
        self.splitter.insert(bridge)
        self.assertEqual(len(self.https_ring), 1)
        self.assertEqual(len(self.moat_ring), 0)

        # ...and now the bridge changes its mind and wants Moat.
        bridge.distribution_request = "moat"
        self.splitter.insert(bridge)
        self.assertEqual(len(self.https_ring), 0)
        self.assertEqual(len(self.moat_ring), 1)

        # self.splitter.filterRings()

    def test_remove(self):
        bridge = self.bridges[0]

        self.https_ring.insert(bridge)
        self.https_distributor.prepopulateRings()
        self.assertEqual(len(self.https_ring), 1)

        self.https_ring.remove(bridge)
        self.assertEqual(len(self.https_ring), 0)
