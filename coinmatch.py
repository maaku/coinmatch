#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright © 2013 by its contributors. See AUTHORS for details.
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from base64 import standard_b64encode, standard_b64decode
import calendar
from datetime import datetime, timedelta
import numbers
import operator
import six
import sys

# ===----------------------------------------------------------------------===

from bitcoin.address import *
from bitcoin.crypto import *
from bitcoin.base58 import *
from bitcoin.mixins import *
from bitcoin.script import *
from bitcoin.serialize import *
from bitcoin.tools import *

# ===----------------------------------------------------------------------===

# SQLAlchemy object-relational mapper
from sqlalchemy import *

# ===----------------------------------------------------------------------===

# SQLAlchemy types. These are custom types used to store bitcoin data and
# CoinJoin cryptographic primitives, performing proper serialization to
# underlying database types as necessary.

from sa_bitcoin.fields.binary import *
from sa_bitcoin.fields.ecdsa_ import *
from sa_bitcoin.fields.hash_ import *
from sa_bitcoin.fields.integer import *
from sa_bitcoin.fields.script import *
from sa_bitcoin.fields.time_ import *

class RsaKey(TypeDecorator):
    impl = LargeBinary

    def __init__(self, length=None, *args, **kwargs):
        super(RsaKey, self).__init__(length, *args, **kwargs)

    def process_bind_param(self, value, dialect):
        return value.exportKey('DER')
    def process_result_value(self, value, dialect):
        return RSA.importKey(value)
    def copy(self):
        return self.__class__(self.impl.length)

# ===----------------------------------------------------------------------===

# SQLAlchemy ORM event registration
from sqlalchemy import event, orm

@event.listens_for(orm.Session, 'before_flush')
def lazy_defaults(session, flush_context, instances):
    "Sets default values that are left unspecified by the application."
    for target in session.new.union(session.dirty):
        if hasattr(target, '__lazy_slots__'):
            # This code may look like it does nothing, but in fact we are using
            # properties to lazily generate values for some columns, so calling
            # `getattr()` evaluates those lazy expressions. This is slightly
            # kludgy.. but necessary as SQLAlchemy never calls `getattr()` before
            # passing the field values to the database layer.
            for attr in target.__lazy_slots__:
                getattr(target, attr)

# ===----------------------------------------------------------------------===

engine = create_engine('sqlite:///coinmatch.sqlite', echo=False)

Base.metadata.create_all(engine)

from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)

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

def get_chain_id(rpc):
    # FIXME: Now that asset tags are hash256, simply process the result of
    #   rpc.getblockhash(0) and return that.
    genesis_block_hash_string = rpc.getblockhash(0)
    genesis_block_dict = rpc.getblock(genesis_block_hash_string)
    genesis_block = core.Block(
        version     = genesis_block_dict['version'],
        parent_hash = 0,
        merkle_hash = hash_string_to_integer(genesis_block_dict['merkleroot']),
        time        = genesis_block_dict['time'],
        bits        = int(u'0x' + genesis_block_dict['bits'], base=16),
        nonce       = genesis_block_dict['nonce'])
    assert (hash256(genesis_block.serialize()).intdigest() ==
            hash_string_to_integer(genesis_block_hash_string))
    return hash256(genesis_block.serialize()).intdigest()

# ===----------------------------------------------------------------------===

from collections import namedtuple
OutPoint = namedtuple('OutPoint', ('hash', 'index'))
Contract = namedtuple('Contract', ('amount', 'script'))

def sync_unspent_outputs(rpc, session):
    asset = get_chain_id(rpc)

    unspent_outputs = dict()
    result = rpc.listunspent()
    for obj in result:
        outpoint = OutPoint(
            hash  = hash_string_to_integer(obj['txid']),
            index = obj['vout'])
        contract = Contract(
            amount = amount_decimal_to_int64(obj['amount']),
            script = script_from_hex_string(obj['scriptPubKey']))
        unspent_outputs[outpoint] = contract

    num_insert = 0
    num_update = 0
    num_delete = 0

    for outpoint,contract in six.iteritems(unspent_outputs):
        output = (session.query(Output)
                         .filter((Output.hash  == outpoint.hash) &
                                 (Output.index == outpoint.index))
                         .first())

        if output is not None:
            assert output.amount   == contract.amount
            assert output.contract == contract.script
            if output.is_mine is True and output.is_spent is False:
                continue
            print 'Update %064x:%d' % (outpoint.hash, outpoint.index)
            output.is_mine  = True
            output.is_spent = False
            num_update += 1

        else:
            print 'Insert %064x:%d' % (outpoint.hash, outpoint.index)
            output = Output(
                asset    = asset,
                hash     = outpoint.hash,
                index    = outpoint.index,
                amount   = contract.amount,
                contract = contract.script,
                is_mine  = True,
                is_spent = False)
            num_insert += 1

        session.add(output)
    session.flush()

    outputs = (session.query(Output)
                      .filter((Output.is_mine  == True) &
                              (Output.is_spent == False)))
    if outputs.count() != len(unspent_outputs):
        for output in outputs.all():
            outpoint = OutPoint(hash=output.hash, index=output.index)
            if outpoint not in unspent_outputs:
                print 'Delete %064x:%d' % (outpoint.hash, outpoint.index)
                output.is_spent = True
                num_delete += 1
                session.add(output)

    session.commit()

    print 'Added % 5d previously unknown outputs' % num_insert
    print 'Reorg\'d % 3d spent outputs as unspent'  % num_update
    print 'Marked % 4d existing outputs as spent' % num_delete

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

if __name__ == '__main__':
    try:
        argv = FLAGS(sys.argv)
    except gflags.FlagsError, e:
        print '%s\n\nUsage %s ARGS \n%s' % (e, sys.argv[0], FLAGS)
        sys.exit(1)

    if FLAGS.testnet:
        class BitcoinTestnetAddress(BitcoinAddress):
            PUBKEY_HASH = 111
            SCRIPT_HASH = 196
        BitcoinAddress = BitcoinTestnetAddress

    else:
        print '%s is NOT ready for primetime; run with --testnet' % sys.argv[0]
        sys.exit(0)

    kwargs = {}
    kwargs['username'] = FLAGS.username
    kwargs['password'] = FLAGS.password
    kwargs['timeout'] = FLAGS.timeout
    from bitcoin.rpc import Proxy
    rpc = Proxy('http://%s:%d/' % (FLAGS.host, FLAGS.port), **kwargs)

    session = Session()

    sync_unspent_outputs(rpc, session)

    import IPython
    IPython.embed()
