# Copyright (C) 2015 by the Massachusetts Institute of Technology.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

import sys

sys.path[:0] = ['/home/tlyu/lib/python']

import base64
import json
import krb5
import urllib
import urlparse

ktname = 'FILE:/home/tlyu/daemon.ulthar.keytab'

def badmethod(env, start_resp):
    start_resp('405 Method not allowed',
               [('Content-type', 'text/plain')])
    return ['bad method']

def fixpad(s):
    r = len(s) % 4
    if r == 1:
        raise TypeError('bad base64 length')
    return s + '=' * ((4 - r) % 4)

def application(env, start_resp):
    if env['REQUEST_METHOD'] != 'POST':
        return badmethod(env, start_resp)

    data = env['wsgi.input'].read(-1)
    query = urlparse.parse_qs(data)
    encval = fixpad(query['ticket'][0])
    data = base64.urlsafe_b64decode(encval)
    rep = main(data) + '\r\n'
    start_resp('200 OK', [('Content-type', 'application/json'),
                          ('Content-length', str(len(rep)))])
    return [rep]

def main(data):
    ctx = krb5.Context()
    tkt = ctx.decode_ticket(data)
    kt = ctx.kt_resolve(ktname)
    kt.decrypt_tkt(tkt)
    encpart = tkt._handle.contents.enc_part2.contents
    d = { }
    cprinc = krb5.PrincipalRef(ctx, encpart.client)
    d['sub'] = cprinc.unparse_name()
    crealm = encpart.client.contents.realm.as_str()
    d['iss'] = 'krbtgt/%s@%s' % (crealm, crealm)
    sprinc = krb5.PrincipalRef(ctx, tkt._handle.contents.server)
    d['aud'] = sprinc.unparse_name()
    d['iat'] = encpart.times.authtime
    d['nbf'] = encpart.times.starttime
    d['exp'] = encpart.times.endtime
    return json.dumps(d, sys.stdout, indent=2, separators=(',', ':'))
