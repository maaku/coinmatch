#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright © 2013 by its contributors. See AUTHORS for details.
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

if __name__ != '__main__':
    raise ImportError(u"%s may only be run as a script" % __file__)

# ===----------------------------------------------------------------------===

import six

from bitcoin.numeric import *
from bitcoin.serialize import *
from bitcoin.tools import *

from pycoin.wallet import Wallet

# ===----------------------------------------------------------------------===

import gflags
FLAGS = gflags.FLAGS

gflags.DEFINE_string('host', u"localhost",
    u"Hostname or network address of RPC server",
    short_name='h')

gflags.DEFINE_integer('port', 8332,
    u"Network port of RPC server",
    short_name='P')
gflags.RegisterValidator('port',
    lambda rpcport: 1 <= rpcport <= 65535,
    message=u"Valid TCP/IP port numbers must be positive integers from 1 to 65535.")

gflags.DEFINE_string('sslcert', None,
    u"File containing server's public key. If specified, the connection must "
    u"be encrypted and the server's SSL certificate match.")

gflags.DEFINE_string('sslciphers',
    u"TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH",
    u"Allowed SSL ciphers. See the OpenSSL documentation for syntax.")

gflags.DEFINE_string('username', None,
    u"Username for connection to RPC server",
    short_name='u')
gflags.MarkFlagAsRequired('username')

gflags.DEFINE_string('password', None,
    u"Username for connection to RPC server",
    short_name='p')
gflags.MarkFlagAsRequired('password')

gflags.DEFINE_integer('timeout', 15,
    u"Timeout for communication with RPC server, or zero to disable")
gflags.RegisterValidator('timeout',
    lambda timeout: 0 <= timeout,
    message=u"Valid timeout setting must be a positive number of seconds, or zero.")

gflags.DEFINE_boolean('testnet', False,
    u"Change bitcoin addresses to use testnet prefixes.")

gflags.DEFINE_string('rootkey', None,
    u"BIP-32 root derivation key.")
gflags.RegisterValidator('rootkey',
    lambda rootkey: rootkey is not None and Wallet.from_wallet_key(rootkey).is_private,
    message=u"Must provide private root derivation key.")
gflags.MarkFlagAsRequired('rootkey')

gflags.DEFINE_boolean('debug', False,
    u"Print extra debugging information to stderr")

gflags.DEFINE_string('foundation_database', u"sqlite:///foundation.sqlite",
    u"Connection string for Freicoin Foundation database")

gflags.DEFINE_string('fee', u"0.0001",
    u"Minimum relay fee, per kB")
def _validate_fee(fee):
    try:
        mpd(fee); return True
    except:
        return False
gflags.RegisterValidator('fee', _validate_fee,
    message=u"Must provide a decimal fee value.")

#gflags.DEFINE_string('cache_database', u"sqlite:///coinmatch.sqlite",
#    u"Connection string for cache database")

# ===----------------------------------------------------------------------===

def hash_string_to_integer(string, size=32):
    return deserialize_hash(StringIO(string.decode('hex')[::-1]), size)

def hash_integer_to_string(integer, size=32):
    return serialize_hash(integer, size)[::-1].encode('hex')

def amount_decimal_to_int64(decimal):
    return int(decimal * 10**8)

def script_from_hex_string(string):
    return Script.deserialize(StringIO(serialize_varchar(string.decode('hex'))))

# ===----------------------------------------------------------------------===

try:
    import sys
    argv = FLAGS(sys.argv)
except gflags.FlagsError, e:
    print '%s\n\nUsage %s ARGS \n%s' % (e, sys.argv[0], FLAGS)
    sys.exit(1)

if FLAGS.testnet:
    import bitcoin.address
    bitcoin.address.BitcoinAddress.PUBKEY_HASH = 111
    bitcoin.address.BitcoinAddress.SCRIPT_HASH = 196

else:
    print '%s is NOT ready for primetime; run with --testnet' % sys.argv[0]
    sys.exit(0)

# ===----------------------------------------------------------------------===

kwargs = {}
kwargs['username'] = FLAGS.username
kwargs['password'] = FLAGS.password
kwargs['timeout'] = FLAGS.timeout
from bitcoin.rpc import Proxy
rpc = Proxy('http://%s:%d/' % (FLAGS.host, FLAGS.port), **kwargs)
assert rpc.getinfo()

# ===----------------------------------------------------------------------===

from recordtype import recordtype
Output = recordtype('Output', ('address', 'amount', 'hash', 'index', 'age'))
outputs = map(
    lambda o:Output(**{
        'address': o[u'address'],
        'amount':  mpq(o[u'amount']),
        'hash':    hash_string_to_integer(o[u'txid']),
        'index':   int(o[u'vout']),
        'age':     int(o[u'confirmations']),
    }),
    rpc.listunspent(),)
outputs.sort(key=lambda o:o.age, reverse=True)

# ===----------------------------------------------------------------------===

wallet = Wallet.from_wallet_key(FLAGS.rootkey)
assert wallet.is_private

# ===----------------------------------------------------------------------===

months = [1, 2, 3, 4]
early_orgs = [13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26, 27]

route = {}
for org_id in early_orgs:
    for month_id in months:
        sk = wallet.subkey_for_path('%d/%d' % (month_id, org_id))
        vk = rpc.validateaddress(sk.bitcoin_address())
        if not ('ismine' in vk and vk['ismine'] is True):
            rpc.importprivkey(sk.wif())
            print 'Added forwarding address %s for org %d, month %d' % (
                sk.bitcoin_address(), org_id, month_id)
        route[sk.bitcoin_address()] = \
              wallet.subkey_for_path('0/%d' % org_id).bitcoin_address()

# ===----------------------------------------------------------------------===

forward_outputs = filter(lambda o:o.address in route.keys(), outputs)
outputs = filter(lambda o:o not in foward_outputs, forward_outputs)

# ===----------------------------------------------------------------------===

# SQLAlchemy object-relational mapper
from sqlalchemy import *

engine = create_engine(FLAGS.foundation_database, echo=FLAGS.debug)

res = engine.execute('''
    SELECT A.id      as id,
           B.address as address
    FROM   donations_organization   as A,
           donations_paymentaddress as B
    WHERE  A.freicoin_address_id = B.id and
           A.validated IS NOT NULL
''')

match = {}
for r in res:
    sk = wallet.subkey_for_path('0/%d' % r.id)
    vk = rpc.validateaddress(sk.bitcoin_address())
    if not ('ismine' in vk and vk['ismine'] is True):
        rpc.importprivkey(sk.wif())
        print 'Added matching address %s for org %d' % (sk.bitcoin_address(), r.id)
    match[sk.bitcoin_address()] = r.address

# ===----------------------------------------------------------------------===

import IPython
IPython.embed()
