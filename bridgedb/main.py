# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_Main -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see the AUTHORS file for attributions
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2013-2017, Matthew Finkel
#             (c) 2007-2017, Nick Mathewson
#             (c) 2007-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""This module sets up BridgeDB and starts the servers running."""

import logging
import os
import signal
import sys
import time

from twisted.internet import reactor
from twisted.internet import task

from bridgedb import crypto
from bridgedb import persistent
from bridgedb import proxy
from bridgedb import runner
from bridgedb import util
from bridgedb import metrics
from bridgedb import antibot
from bridgedb.bridges import MalformedBridgeInfo
from bridgedb.bridges import MissingServerDescriptorDigest
from bridgedb.bridges import ServerDescriptorDigestMismatch
from bridgedb.bridges import ServerDescriptorWithoutNetworkstatus
from bridgedb.bridges import Bridge
from bridgedb.configure import loadConfig
from bridgedb.distributors.email.distributor import EmailDistributor
from bridgedb.distributors.https.distributor import HTTPSDistributor
from bridgedb.distributors.moat.distributor import MoatDistributor
from bridgedb.parse import descriptors
from bridgedb.parse.blacklist import parseBridgeBlacklistFile

import bridgedb.Storage

from bridgedb import Bridges
from bridgedb.Stability import updateBridgeHistory


def expandBridgeAuthDir(authdir, filename):
    """Expands a descriptor ``filename`` relative to which of the
    BRIDGE_AUTHORITY_DIRECTORIES, ``authdir`` it resides within.
    """
    path = filename

    if not authdir in filename or not os.path.isabs(filename):
        path = os.path.abspath(os.path.expanduser(os.sep.join([authdir, filename])))

    return path

def writeAssignments(hashring, filename):
    """Dump bridge distributor assignments to disk.

    :type hashring: A :class:`~bridgedb.Bridges.BridgeSplitter`
    :ivar hashring: A class which takes an HMAC key and splits bridges
        into their hashring assignments.
    :param str filename: The filename to write the assignments to.
    """
    logging.debug("Dumping pool assignments to file: '%s'" % filename)

    try:
        with open(filename, 'a') as fh:
            fh.write("bridge-pool-assignment %s\n" %
                     time.strftime("%Y-%m-%d %H:%M:%S"))
            hashring.dumpAssignments(fh)
    except IOError:
        logging.info("I/O error while writing assignments to: '%s'" % filename)

def writeMetrics(filename, measurementInterval):
    """Dump usage metrics to disk.

    :param str filename: The filename to write the metrics to.
    :param int measurementInterval: The number of seconds after which we rotate
        and dump our metrics.
    """

    logging.debug("Dumping metrics to file: '%s'" % filename)

    try:
        with open(filename, 'w') as fh:
            metrics.export(fh, measurementInterval)
    except IOError as err:
        logging.error("Failed to write metrics to '%s': %s" % (filename, err))

def load(state, hashring, clear=False):
    """Read and parse all descriptors, and load into a bridge hashring.

    Read all the appropriate bridge files from the saved
    :class:`~bridgedb.persistent.State`, parse and validate them, and then
    store them into our ``state.hashring`` instance. The ``state`` will be
    saved again at the end of this function.

    :type hashring: :class:`~bridgedb.Bridges.BridgeSplitter`
    :param hashring: A class which provides a mechanism for HMACing
        Bridges in order to assign them to hashrings.
    :param boolean clear: If True, clear all previous bridges from the
        hashring before parsing for new ones.
    """
    if not state:
        logging.fatal("bridgedb.main.load() could not retrieve state!")
        sys.exit(2)

    if clear:
        logging.info("Clearing old bridges...")
        hashring.clear()

    logging.info("Loading bridges...")

    ignoreNetworkstatus = state.IGNORE_NETWORKSTATUS
    if ignoreNetworkstatus:
        logging.info("Ignoring BridgeAuthority networkstatus documents.")

    for auth in state.BRIDGE_AUTHORITY_DIRECTORIES:
        logging.info("Processing descriptors in %s directory..." % auth)

        bridges = {}
        timestamps = {}

        fn = expandBridgeAuthDir(auth, state.STATUS_FILE)
        logging.info("Opening networkstatus file: %s" % fn)
        networkstatuses = descriptors.parseNetworkStatusFile(fn)
        logging.debug("Closing networkstatus file: %s" % fn)

        logging.info("Processing networkstatus descriptors...")
        for router in networkstatuses:
            bridge = Bridge()
            bridge.updateFromNetworkStatus(router, ignoreNetworkstatus)
            try:
                bridge.assertOK()
            except MalformedBridgeInfo as error:
                logging.warn(str(error))
            else:
                bridges[bridge.fingerprint] = bridge

        for filename in state.BRIDGE_FILES:
            fn = expandBridgeAuthDir(auth, filename)
            logging.info("Opening bridge-server-descriptor file: '%s'" % fn)
            serverdescriptors = descriptors.parseServerDescriptorsFile(fn)
            logging.debug("Closing bridge-server-descriptor file: '%s'" % fn)

            for router in serverdescriptors:
                try:
                    bridge = bridges[router.fingerprint]
                except KeyError:
                    logging.warn(
                        ("Received server descriptor for bridge '%s' which wasn't "
                         "in the networkstatus!") % router.fingerprint)
                    if ignoreNetworkstatus:
                        bridge = Bridge()
                    else:
                        continue

                try:
                    bridge.updateFromServerDescriptor(router, ignoreNetworkstatus)
                except (ServerDescriptorWithoutNetworkstatus,
                        MissingServerDescriptorDigest,
                        ServerDescriptorDigestMismatch) as error:
                    logging.warn(str(error))
                    # Reject any routers whose server descriptors didn't pass
                    # :meth:`~bridges.Bridge._checkServerDescriptor`, i.e. those
                    # bridges who don't have corresponding networkstatus
                    # documents, or whose server descriptor digests don't check
                    # out:
                    bridges.pop(router.fingerprint)
                    continue

                if state.COLLECT_TIMESTAMPS:
                    # Update timestamps from server descriptors, not from network
                    # status descriptors (because networkstatus documents and
                    # descriptors aren't authenticated in any way):
                    if bridge.fingerprint in timestamps.keys():
                        timestamps[bridge.fingerprint].append(router.published)
                    else:
                        timestamps[bridge.fingerprint] = [router.published]

        eifiles = [expandBridgeAuthDir(auth, fn) for fn in state.EXTRA_INFO_FILES]
        extrainfos = descriptors.parseExtraInfoFiles(*eifiles)
        for fingerprint, router in extrainfos.items():
            try:
                bridges[fingerprint].updateFromExtraInfoDescriptor(router)
            except MalformedBridgeInfo as error:
                logging.warn(str(error))
            except KeyError as error:
                logging.warn(("Received extrainfo descriptor for bridge '%s', "
                              "but could not find bridge with that fingerprint.")
                             % router.fingerprint)

        blacklist = parseBridgeBlacklistFile(state.NO_DISTRIBUTION_FILE)

        inserted = 0
        logging.info("Trying to insert %d bridges into hashring, %d of which "
                     "have the 'Running' flag..." % (len(bridges),
                     len(list(filter(lambda b: b.flags.running, bridges.values())))))

        for fingerprint, bridge in bridges.items():
            # Skip insertion of bridges which are geolocated to be in one of the
            # NO_DISTRIBUTION_COUNTRIES, a.k.a. the countries we don't distribute
            # bridges from:
            if bridge.country in state.NO_DISTRIBUTION_COUNTRIES:
                logging.warn("Not distributing Bridge %s %s:%s in country %s!" %
                             (bridge, bridge.address, bridge.orPort, bridge.country))
            # Skip insertion of blacklisted bridges.
            elif bridge in blacklist.keys():
                logging.warn("Not distributing blacklisted Bridge %s %s:%s: %s" %
                             (bridge, bridge.address, bridge.orPort, blacklist[bridge]))
            else:
                # If the bridge is not running, then it is skipped during the
                # insertion process.
                hashring.insert(bridge)
                inserted += 1
        logging.info("Tried to insert %d bridges into hashring.  Resulting "
                     "hashring is of length %d." % (inserted, len(hashring)))

        if state.COLLECT_TIMESTAMPS:
            reactor.callInThread(updateBridgeHistory, bridges, timestamps)

        state.save()

def _reloadFn(*args):
    """Placeholder callback function for :func:`_handleSIGHUP`."""
    return True

def _handleSIGHUP(*args):
    """Called when we receive a SIGHUP; invokes _reloadFn."""
    reactor.callInThread(_reloadFn)

def replaceBridgeRings(current, replacement):
    """Replace the current thing with the new one"""
    current.hashring = replacement.hashring

def createBridgeRings(cfg, proxyList, key):
    """Create the bridge distributors defined by the config file

    :type cfg:  :class:`Conf`
    :param cfg: The current configuration, including any in-memory settings
        (i.e. settings whose values were not obtained from the config file,
        but were set via a function somewhere)
    :type proxyList: :class:`~bridgedb.proxy.ProxySet`
    :param proxyList: The container for the IP addresses of any currently
        known open proxies.
    :param bytes key: Hashring master key
    :rtype: tuple
    :returns: A :class:`~bridgedb.Bridges.BridgeSplitter` hashring, an
        :class:`~bridgedb.distributors.https.distributor.HTTPSDistributor` or None, and an
        :class:`~bridgedb.distributors.email.distributor.EmailDistributor` or None, and an
        :class:`~bridgedb.distributors.moat.distributor.MoatDistributor` or None.
    """
    # Create a BridgeSplitter to assign the bridges to the different
    # distributors.
    hashring = Bridges.BridgeSplitter(crypto.getHMAC(key, "Hashring-Key"))
    logging.debug("Created hashring: %r" % hashring)

    # Create ring parameters.
    ringParams = Bridges.BridgeRingParameters(needPorts=cfg.FORCE_PORTS,
                                              needFlags=cfg.FORCE_FLAGS)

    emailDistributor = ipDistributor = moatDistributor = None

    # As appropriate, create a Moat distributor.
    if cfg.MOAT_DIST and cfg.MOAT_SHARE:
        logging.debug("Setting up Moat Distributor...")
        moatDistributor = MoatDistributor(
            cfg.MOAT_N_IP_CLUSTERS,
            crypto.getHMAC(key, "Moat-Dist-Key"),
            proxyList,
            answerParameters=ringParams)
        hashring.addRing(moatDistributor.hashring, "moat", cfg.MOAT_SHARE)

    # As appropriate, create an IP-based distributor.
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        logging.debug("Setting up HTTPS Distributor...")
        ipDistributor = HTTPSDistributor(
            cfg.N_IP_CLUSTERS,
            crypto.getHMAC(key, "HTTPS-IP-Dist-Key"),
            proxyList,
            answerParameters=ringParams)
        hashring.addRing(ipDistributor.hashring, "https", cfg.HTTPS_SHARE)

    # As appropriate, create an email-based distributor.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        logging.debug("Setting up Email Distributor...")
        emailDistributor = EmailDistributor(
            crypto.getHMAC(key, "Email-Dist-Key"),
            cfg.EMAIL_DOMAIN_MAP.copy(),
            cfg.EMAIL_DOMAIN_RULES.copy(),
            answerParameters=ringParams,
            whitelist=cfg.EMAIL_WHITELIST.copy())
        hashring.addRing(emailDistributor.hashring, "email", cfg.EMAIL_SHARE)

    # As appropriate, tell the hashring to leave some bridges unallocated.
    if cfg.RESERVED_SHARE:
        hashring.addRing(Bridges.UnallocatedHolder(),
                         "unallocated",
                         cfg.RESERVED_SHARE)

    return hashring, emailDistributor, ipDistributor, moatDistributor

def run(options, reactor=reactor):
    """This is BridgeDB's main entry point and main runtime loop.

    Given the parsed commandline options, this function handles locating the
    configuration file, loading and parsing it, and then either (re)parsing
    plus (re)starting the servers, or dumping bridge assignments to files.

    :type options: :class:`bridgedb.parse.options.MainOptions`
    :param options: A pre-parsed options class containing any arguments and
        options given in the commandline we were called with.
    :type state: :class:`bridgedb.persistent.State`
    :ivar state: A persistent state object which holds config changes.
    :param reactor: An implementer of
        :api:`twisted.internet.interfaces.IReactorCore`. This parameter is
        mainly for testing; the default
        :api:`twisted.internet.epollreactor.EPollReactor` is fine for normal
        application runs.
    """
    # Change to the directory where we're supposed to run. This must be done
    # before parsing the config file, otherwise there will need to be two
    # copies of the config file, one in the directory BridgeDB is started in,
    # and another in the directory it changes into.
    os.chdir(options['rundir'])
    if options['verbosity'] <= 10: # Corresponds to logging.DEBUG
        print("Changed to runtime directory %r" % os.getcwd())

    config = loadConfig(options['config'])
    config.RUN_IN_DIR = options['rundir']

    # Set up logging as early as possible. We cannot import from the bridgedb
    # package any of our modules which import :mod:`logging` and start using
    # it, at least, not until :func:`safelog.configureLogging` is
    # called. Otherwise a default handler that logs to the console will be
    # created by the imported module, and all further calls to
    # :func:`logging.basicConfig` will be ignored.
    util.configureLogging(config)

    if options.subCommand is not None:
        runSubcommand(options, config)

    # Write the pidfile only after any options.subCommands are run (because
    # these exit when they are finished). Otherwise, if there is a subcommand,
    # the real PIDFILE would get overwritten with the PID of the temporary
    # bridgedb process running the subcommand.
    if config.PIDFILE:
        logging.debug("Writing server PID to file: '%s'" % config.PIDFILE)
        with open(config.PIDFILE, 'w') as pidfile:
            pidfile.write("%s\n" % os.getpid())
            pidfile.flush()

    # Let our pluggable transport class know what transports are resistant to
    # active probing.  We need to know because we shouldn't hand out a
    # probing-vulnerable transport on a bridge that supports a
    # probing-resistant transport.  See
    # <https://bugs.torproject.org/28655> for details.
    from bridgedb.bridges import PluggableTransport
    PluggableTransport.probing_resistant_transports = config.PROBING_RESISTANT_TRANSPORTS

    from bridgedb import persistent

    state = persistent.State(config=config)

    from bridgedb.distributors.email.server import addServer as addSMTPServer
    from bridgedb.distributors.https.server import addWebServer
    from bridgedb.distributors.moat.server  import addMoatServer

    # Load the master key, or create a new one.
    key = crypto.getKey(config.MASTER_KEY_FILE)
    proxies = proxy.ProxySet()
    emailDistributor = None
    ipDistributor = None
    moatDistributor = None

    # Save our state
    state.key = key
    state.save()

    def reload(inThread=True): # pragma: no cover
        """Reload settings, proxy lists, and bridges.

        State should be saved before calling this method, and will be saved
        again at the end of it.

        The internal variables ``cfg`` and ``hashring`` are taken from a
        :class:`~bridgedb.persistent.State` instance, which has been saved to a
        statefile with :meth:`bridgedb.persistent.State.save`.

        :type cfg: :class:`Conf`
        :ivar cfg: The current configuration, including any in-memory
            settings (i.e. settings whose values were not obtained from the
            config file, but were set via a function somewhere)
        :type hashring: A :class:`~bridgedb.Bridges.BridgeSplitter`
        :ivar hashring: A class which takes an HMAC key and splits bridges
            into their hashring assignments.
        """
        logging.debug("Caught SIGHUP")
        logging.info("Reloading...")

        logging.info("Loading saved state...")
        state = persistent.load()
        cfg = loadConfig(state.CONFIG_FILE, state.config)
        logging.info("Updating any changed settings...")
        state.useChangedSettings(cfg)

        level = getattr(state, 'LOGLEVEL', 'WARNING')
        logging.info("Updating log level to: '%s'" % level)
        level = getattr(logging, level)
        logging.getLogger().setLevel(level)

        logging.info("Reloading the list of open proxies...")
        for proxyfile in cfg.PROXY_LIST_FILES:
            logging.info("Loading proxies from: %s" % proxyfile)
            proxy.loadProxiesFromFile(proxyfile, proxies, removeStale=True)
        metrics.setProxies(proxies)

        logging.info("Reloading blacklisted request headers...")
        antibot.loadBlacklistedRequestHeaders(config.BLACKLISTED_REQUEST_HEADERS_FILE)
        logging.info("Reloading decoy bridges...")
        antibot.loadDecoyBridges(config.DECOY_BRIDGES_FILE)

        (hashring,
         emailDistributorTmp,
         ipDistributorTmp,
         moatDistributorTmp) = createBridgeRings(cfg, proxies, key)

        # Initialize our DB.
        bridgedb.Storage.initializeDBLock()
        bridgedb.Storage.setDBFilename(cfg.DB_FILE + ".sqlite")
        logging.info("Reparsing bridge descriptors...")
        load(state, hashring, clear=False)
        logging.info("Bridges loaded: %d" % len(hashring))

        if emailDistributorTmp is not None:
            emailDistributorTmp.prepopulateRings() # create default rings
        else:
            logging.warn("No email distributor created!")

        if ipDistributorTmp is not None:
            ipDistributorTmp.prepopulateRings() # create default rings
        else:
            logging.warn("No HTTP(S) distributor created!")

        if moatDistributorTmp is not None:
            moatDistributorTmp.prepopulateRings()
        else:
            logging.warn("No Moat distributor created!")

        # Dump bridge pool assignments to disk.
        writeAssignments(hashring, state.ASSIGNMENTS_FILE)
        state.save()

        if inThread:
            # XXX shutdown the distributors if they were previously running
            # and should now be disabled
            if moatDistributorTmp:
                reactor.callFromThread(replaceBridgeRings,
                                       moatDistributor, moatDistributorTmp)
            if ipDistributorTmp:
                reactor.callFromThread(replaceBridgeRings,
                                       ipDistributor, ipDistributorTmp)
            if emailDistributorTmp:
                reactor.callFromThread(replaceBridgeRings,
                                       emailDistributor, emailDistributorTmp)
        else:
            # We're still starting up. Return these distributors so
            # they are configured in the outer-namespace
            return emailDistributorTmp, ipDistributorTmp, moatDistributorTmp

    global _reloadFn
    _reloadFn = reload
    signal.signal(signal.SIGHUP, _handleSIGHUP)

    if reactor:  # pragma: no cover
        # And actually load it to start parsing. Get back our distributors.
        emailDistributor, ipDistributor, moatDistributor = reload(False)

        # Configure all servers:
        if config.MOAT_DIST and config.MOAT_SHARE:
            addMoatServer(config, moatDistributor)
        if config.HTTPS_DIST and config.HTTPS_SHARE:
            addWebServer(config, ipDistributor)
        if config.EMAIL_DIST and config.EMAIL_SHARE:
            addSMTPServer(config, emailDistributor)

        metrics.setSupportedTransports(config.SUPPORTED_TRANSPORTS)

        tasks = {}

        # Setup all our repeating tasks:
        if config.TASKS['GET_TOR_EXIT_LIST']:
            tasks['GET_TOR_EXIT_LIST'] = task.LoopingCall(
                proxy.downloadTorExits,
                proxies,
                config.SERVER_PUBLIC_EXTERNAL_IP)

        if config.TASKS.get('DELETE_UNPARSEABLE_DESCRIPTORS'):
            delUnparseableSecs = config.TASKS['DELETE_UNPARSEABLE_DESCRIPTORS']
        else:
            delUnparseableSecs = 24 * 60 * 60  # Default to 24 hours

        # We use the directory name of STATUS_FILE, since that directory
        # is where the *.unparseable descriptor files will be written to.
        tasks['DELETE_UNPARSEABLE_DESCRIPTORS'] = task.LoopingCall(
            runner.cleanupUnparseableDescriptors,
            os.path.dirname(config.STATUS_FILE), delUnparseableSecs)

        measurementInterval, _ = config.TASKS['EXPORT_METRICS']
        tasks['EXPORT_METRICS'] = task.LoopingCall(
            writeMetrics, state.METRICS_FILE, measurementInterval)

        # Schedule all configured repeating tasks:
        for name, value in config.TASKS.items():
            seconds, startNow = value
            if seconds:
                try:
                    # Set now to False to get the servers up and running when
                    # first started, rather than spend a bunch of time in
                    # scheduled tasks.
                    tasks[name].start(abs(seconds), now=startNow)
                except KeyError:
                    logging.info("Task %s is disabled and will not run." % name)
                else:
                    logging.info("Scheduled task %s to run every %s seconds."
                                 % (name, seconds))

    # Actually run the servers.
    try:
        if reactor and not reactor.running:
            logging.info("Starting reactors.")
            reactor.run()
    except KeyboardInterrupt: # pragma: no cover
        logging.fatal("Received keyboard interrupt. Shutting down...")
    finally:
        if config.PIDFILE:
            os.unlink(config.PIDFILE)
        logging.info("Exiting...")
        sys.exit()

def runSubcommand(options, config):
    """Run a subcommand from the 'Commands' section of the bridgedb help menu.

    :type options: :class:`bridgedb.opt.MainOptions`
    :param options: A pre-parsed options class containing any arguments and
        options given in the commandline we were called with.
    :type config: :class:`bridgedb.main.Conf`
    :param config: The current configuration.
    :raises: :exc:`SystemExit` when all subCommands and subOptions have
        finished running.
    """
    # Make sure that the runner module is only imported after logging is set
    # up, otherwise we run into the same logging configuration problem as
    # mentioned above with the email.server and https.server.
    from bridgedb import runner

    if options.subCommand is not None:
        logging.debug("Running BridgeDB command: '%s'" % options.subCommand)

        if 'descriptors' in options.subOptions:
            runner.generateDescriptors(int(options.subOptions['descriptors']), config.RUN_IN_DIR)
        sys.exit(0)
