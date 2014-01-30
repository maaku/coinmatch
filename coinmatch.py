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
    print('%s\n\nUsage %s ARGS \n%s' % (e, sys.argv[0], FLAGS))
    sys.exit(0)

if FLAGS.testnet:
    import bitcoin.address
    bitcoin.address.BitcoinAddress.PUBKEY_HASH = 111
    bitcoin.address.BitcoinAddress.SCRIPT_HASH = 196

else:
    print('%s is NOT ready for primetime; run with --testnet' % sys.argv[0])
    sys.exit(1)

# ===----------------------------------------------------------------------===

def get_rpc(flags):
    kwargs = {}
    kwargs['username'] = flags.username
    kwargs['password'] = flags.password
    kwargs['timeout'] = flags.timeout
    from bitcoin.rpc import Proxy
    return Proxy('http://%s:%d/' % (flags.host, flags.port), **kwargs)

from recordtype import recordtype
UnspentOutput = recordtype('UnspentOutput',
    ('address', 'amount', 'hash', 'index', 'value', 'age'))

def get_fund_outputs(rpc):
    fund_outputs = map(
        lambda o:UnspentOutput(**{
            'address': o[u'address'],
            'value':   mpd(o[u'amount']),
            'hash':    hash_string_to_integer(o[u'txid']),
            'index':   int(o[u'vout']),
            'amount':  rpc.decoderawtransaction(rpc.getrawtransaction(o[u'txid'])
                        )['vout'][o[u'vout']]['value'],
            'age':     int(o[u'confirmations']),
        }),
        rpc.listunspent(),)
    fund_outputs.sort(key=lambda o:o.age, reverse=True)
    return fund_outputs

def add_old_addresses(rpc, wallet):
    months = [1, 2, 3, 4]
    early_orgs = [13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26, 27]

    route = {}
    for org_id in early_orgs:
        for month_id in months:
            sk = wallet.subkey_for_path('%d/%d' % (month_id, org_id))
            vk = rpc.validateaddress(sk.bitcoin_address())
            if not ('ismine' in vk and vk['ismine'] is True):
                rpc.importprivkey(sk.wif())
                print('Added forwarding address %s for org %d, month %d' % (
                    sk.bitcoin_address(), org_id, month_id))
            route[sk.bitcoin_address()] = \
                  wallet.subkey_for_path('0/%d' % org_id).bitcoin_address()
    return route

from bitcoin.address import BitcoinAddress
from bitcoin.base58 import VersionedPayload

def add_current_addresses(rpc, wallet, foundation_database, debug):
    # SQLAlchemy object-relational mapper
    from sqlalchemy import *

    engine = create_engine(foundation_database, echo=debug)

    res = engine.execute('''
        SELECT A.id      as id,
               B.address as address
        FROM   donations_organization   as A,
               donations_paymentaddress as B
        WHERE  A.freicoin_address_id = B.id and
               A.validated IS NOT NULL
    ''')

    versions = {0: BitcoinAddress.PUBKEY_HASH,
                5: BitcoinAddress.SCRIPT_HASH}

    match = {}
    for r in res:
        sk = wallet.subkey_for_path('0/%d' % r.id)
        vk = rpc.validateaddress(sk.bitcoin_address())
        if not ('ismine' in vk and vk['ismine'] is True):
            rpc.importprivkey(sk.wif())
            print('Added matching address %s for org %d' % (
                sk.bitcoin_address(), r.id))
        address = VersionedPayload(r.address.decode('base58'))
        match[sk.bitcoin_address()] = BitcoinAddress(
            version = versions[address.version],
            payload = address.payload).encode('base58')

    return match

class OutOfCoinsError(BaseException):
    pass

def submit_transaction(rpc, fund_outputs, current_height, inputs, outputs, **kwargs):
    fee_outputs = 0
    input_value = sum(map(lambda o:o.value, inputs))
    output_value = sum(outputs.values()) / COIN
    while input_value < (output_value + FEE_PER_KB):
        if fee_outputs == len(fund_outputs):
            raise OutOfCoinsError(u"ran out of coins to complete transaction")
        input_value += fund_outputs[fee_outputs].value
        fee_outputs += 1
    change_output = None
    if fee_outputs and (input_value - output_value) >= 2*FEE_PER_KB:
        change = input_value - output_value - FEE_PER_KB
        change_output = UnspentOutput(
            address = fund_outputs[fee_outputs-1].address,
            value   = change,
            hash    = 0, # This isn't known until after tx signing
            index   = 0xffffffff,
            amount  = int(change * COIN),
            age     = 0,)
        change_script = BitcoinAddress(
                change_output.address.decode('base58')
            ).destination.script
        outputs.setdefault(change_script, 0)
        outputs[change_script] += change_output.amount
    inputs.update(fund_outputs[:fee_outputs])

    kwargs.setdefault('version', 2)
    kwargs.setdefault('reference_height', current_height)
    t = Transaction(**kwargs)
    for o in inputs:
        t.inputs.append(Input(**{
            'hash':     o.hash,
            'index':    o.index,
            'sequence': 0,
        }))
    for contract,amount in six.iteritems(outputs):
        t.outputs.append(Output(**{
            'amount':   amount,
            'contract': contract,
        }))

    input_value = sum(map(lambda o:o.value, inputs))
    output_value = sum(outputs.values()) / COIN
    assert input_value < output_value + 2*FEE_PER_KB

    res = rpc.signrawtransaction(t.serialize().encode('hex'))
    assert res[u'complete'] is True and u'hex' in res
    txid = rpc.sendrawtransaction(res[u'hex'])

    fund_outputs = fund_outputs[fee_outputs:]
    if change_output is not None:
        change_output.hash  = hash_string_to_integer(txid)
        change_output.index = t.outputs.index(Output(
            amount = change_output.amount, contract = change_script))
        fund_outputs.append(change_output)

    print(u'Sent transaction %s: %s' % res[u'hex'])

    return txid, res[u'hex']

from recordtype import recordtype
OutPoint = recordtype('OutPoint', ('txid', 'n'))

def has_color(output, color, match):
    txid = hash_integer_to_string(output.hash)
    res = rpc.getrawtransaction(txid)
    res = rpc.decoderawtransaction(res)
    outpoints = set(OutPoint(i['txid'], i['vout']) for i in res['vin'])
    cycle = False
    while outpoints:
        out = outpoints.pop()
        res = rpc.getrawtransaction(out.txid)
        res = rpc.decoderawtransaction(res)
        if 'coinbase' in res['vin'][0]:
            continue
        if color in res['vout'][out.n]['scriptPubKey']['addresses']:
            print('Output %s is cycling coins from %s:%d; exiting' % (
                repr(output), out.txid, out.n))
            return True
        if any(addr in match.keys() for addr in
               res['vout'][out.n]['scriptPubKey']['addresses']):
            continue
        for in_ in res['vin']:
            outpoints.add(OutPoint(in_['txid'], in_['vout']))
    print('Output %s is cycle-free' % repr(output))
    return False

# ===----------------------------------------------------------------------===

rpc = get_rpc(FLAGS)
assert rpc.getinfo()

fund_outputs = get_fund_outputs(rpc)

wallet = Wallet.from_wallet_key(FLAGS.rootkey)
assert wallet.is_private

current_height = rpc.getblockcount()

route = add_old_addresses(rpc, wallet)

match = add_current_addresses(rpc, wallet, FLAGS.foundation_database, FLAGS.debug):

# Separate old outputs from funds
route_outputs = filter(lambda o:o.address in route.keys(), fund_outputs)
fund_outputs = filter(lambda o:o not in route_outputs, fund_outputs)

# Separate match outputs from funds
match_outputs = filter(lambda o:o.address in match.keys(), fund_outputs)
fund_outputs = filter(lambda o:o not in match_outputs, fund_outputs)

# ===----------------------------------------------------------------------===

COIN = mpd('100000000')
FEE_PER_KB = mpd(FLAGS.fee)
MATCH_DELAY = 144 * 30

from bitcoin.address import BitcoinAddress
from bitcoin.core import Transaction, Input, Output

for o in route_outputs:
    amount = int(o.value * COIN)
    script = BitcoinAddress(route[o.address].decode('base58')).destination.script
    inputs = {o,}
    outputs = {script: amount,}
    txid, txhex = submit_transaction(rpc, fund_outputs, current_height, inputs, outputs)
    match_outputs.append(UnspentOutput(**{
        'address': route[o.address],
        'value':   amount / COIN,
        'hash':    hash_string_to_integer(txid),
        'index':   Transaction.deserialize(StringIO(txhex.decode('hex'))
                   ).outputs.index(Output(amount=amount, contract=script)),
        'age':     0,}))

for o in match_outputs:
    out_value = o.value
    if not has_color(o, o.address, match):
        out_value = 11 * out_value / 10
    inputs = {o,}
    outputs = {
        BitcoinAddress(match[o.address].decode('base58')).destination.script:
            int(out_value * COIN),}
    submit_transaction(rpc, fund_outputs, current_height, inputs, outputs,
        lock_time = current_height - o.age + MATCH_DELAY)

# ===----------------------------------------------------------------------===

print("All done!")
