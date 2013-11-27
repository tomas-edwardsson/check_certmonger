#!/usr/bin/python

# Copyright 2013, Tomas Edwardsson 
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from pynag.Plugins import simple as Plugin
from pynag.Plugins import WARNING, UNKNOWN, OK, CRITICAL
from subprocess import Popen, PIPE
import re
import datetime
import sys

np = None

def main():
    global np
    np = Plugin(must_threshold=False)

    np.add_arg('w', 
               'warning', 
               'Warn when X days until certificate expires', 
               required=None)
    np.add_arg('c', 
               'critical', 
               'Critical when X days until certificate expires', 
               required=None)

    np.activate()

    if np['warning'] is None:
        np['warning'] = "14"
    if np['critical'] is None:
        np['critical'] = "2"

    for t in ['warning', 'critical']:
        if np[t] and np[t].isdigit() is False:
            print "%s threshold must be a positive number" % t.capitalize()
            sys.exit(3)

    certs = getcert_list()

    for cert in certs:
        if cert['stuck'] != "no":
            np.add_message(
                   WARNING, 
                   "Certificate %s from certdb %s is stuck=%s" % (
                       cert['certificate']['nickname'], 
                       cert['certificate']['location'],
                       cert['stuck']))

        expires_diff = cert['expires'] - datetime.datetime.now()
        if expires_diff.days < 0:
            np.add_message(
                   CRITICAL,
                   "Certificate %s from certdb %s has EXPIRED %i days ago" % (
                       cert['certificate']['nickname'], 
                       cert['certificate']['location'],
                       expires_diff.days*-1))

        elif expires_diff.days < int(np['critical']):
            np.add_message(
                   CRITICAL,
                   "Certificate %s from certdb %s expires in %i days" % (
                       cert['certificate']['nickname'], 
                       cert['certificate']['location'],
                       expires_diff.days))

        elif expires_diff.days < int(np['warning']):
            np.add_message(
                   WARNING,
                   "Certificate %s from certdb %s expires in %i days" % (
                       cert['certificate']['nickname'], 
                       cert['certificate']['location'],
                       expires_diff.days))

        else:
            np.add_message(
                   OK,
                   "Certificate %s from certdb %s expires in %i days" % (
                       cert['certificate']['nickname'], 
                       cert['certificate']['location'],
                       expires_diff.days))

    code, messages = np.check_messages(joinallstr="\n")
    np.nagios_exit(code, messages)

def getcert_list():
    global np
    certs = []

    request_re = re.compile("Requ.*'(\d+)':")

    try:
        p = Popen(["sudo", "getcert", "list"], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
    except Exception, e:
        np.nagios_exit(UNKNOWN, "Unable to execute \"getcert list\": %s" % e)

    for l in stdout.split("\n"):
        if l.startswith("Number of certificates") or not l:
            continue 

        # Next certificate
        if l.startswith("Request"):
            m = request_re.match(l)
            certs.append( { 'id': m.group(1)})
            continue

        l = l.strip()
        key, v = re.split('\s*:\s*', l, 1)

        if key == "expires":
            v = datetime.datetime.strptime(v, "%Y-%m-%d %H:%M:%S %Z")
        elif key == "certificate" or key == "key pair storage":
            v = parse_fields(v)
        certs[-1][key] = v
    return certs


def parse_fields(text):
    pos = 0
    exp = re.compile(r"""(['"]?)(.*?)\1(,|$)""")

    results = {}

    while True:
        m = exp.search(text, pos)
        result = m.group(2)
        separator = m.group(3)

        k, v = result.split('=', 1)
        if v.startswith("'") and v.endswith("'"):
            v = v[1:-1]
        results[k] = v

        if not separator:
            break

        pos = m.end(0)

    return results



if __name__ == "__main__":
    main()
