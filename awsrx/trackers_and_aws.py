#! /usr/bin/python2.7
#coding=cp850
#mcit@geus.dk
#
#rev. 21/3/2017 - add publish_to_ftp() and implement delivery of raw Freya data to ZAMG
#rev. 13/7/2017 - allow glob-style wildcards in filename passed to publish_to_ftp
#               - implement delivery of raw CEN_T data including malformed
#               - add -8191 to the values decoded as -INF (not sure if -8190 was a typo)
#rev. 08/2/2018 - add ability to append station name if known (relies on imei2name)
#rev. 08/2/2018 - publish_to_ftp() can be set to only publish the n most recent records
#rev. 19/2/2018 - don't ask for passwords if they can be read from a file under the 
#                 user's profile on the local machine (as secure as your geus pc is...)
#               - cleaned up some try/except logic
#               - dont't cast sbd_data['imei'] from str to int
#rev. 23/2/2018 - lots of changes to implement writing the columns headers at the top 
#                 of the csv files, the info is parsed out directly from the CRBasic
#                 program running in the logger. For now it's only for human use, the 
#                 actual binary decoding still uses the ugly payload_fmt dictionary
#rev. 20/6/2018 - nicer handling of ftp errors (special thanks to GEUS IT for surprise 
#                 discontinuation of ftp.geus.dk, thus triggering the bug...)
#rev. 02/7/2018 - add shebang for python launcher to pick py27
#rev. 14/2/2019 - add ftp to UWN
#rev  18/2/2019   preconfigured next available binary format (12)
#rev  12/09/2019  added THE VERSION-3!
#     07/11/2019  added debug decoding activated by uppercase number format letters
#     08/11/2019  now error messages print the full traceback including line number
#     ??          did I fix the gps decoding at some point and forgot? It works now
#     22/09/2020  cleanup some of the unused code and outdated comments before uploading to github

from sorter import sorter
from tailer import tailer

from pprint import pprint

import imaplib
from ssl import PROTOCOL_TLSv1_2
import socket
import ssl
import email
from functools import partial
import re
import os, os.path
import struct
import subprocess as sp
import time, datetime, calendar
import warnings
import base64
import getpass
import os
import ftplib
import sys
import traceback
from ConfigParser import SafeConfigParser
from glob import glob
from collections import OrderedDict

#hack=True for using promice@asterix2.citterio.net if the mailserver is up
hack = False

programs_dir = os.sep.join(('..', 'logger_programs'))

credentials_file = "credentials.ini" # this should be somewhere secure
accounts_ini = SafeConfigParser()
accounts_ini.readfp(open('accounts.ini'))
accounts_ini.read(credentials_file) #optional, contains passwords, keep private

imei_file = 'imei2name.ini'
imei_ini = SafeConfigParser()
imei_ini.readfp(open(imei_file))
imei_names = dict(imei_ini.items('imei_to_name'))
old= {300234061470510: 'QAS_U',
           300234061476520: 'KAN_M',
           300234061478500: 'UPE_L',
           300234061479480: 'GEUS',
           300234061293280: 'KAN_L',
           300234061295270: 'NUK_U',
           300234061852400: 'ZAMG',
           300234061165160: 'KAN_U',
           300234061299270: 'NUK_K',
           300234061627590: 'EGP',
           300234061217540: 'UWN',
           300034012250840: 'THU_L',
           300034012252840: 'THU_U',
           300234064121930: 'CEN_T',
           300234064126980: 'KPC_L',
           300034012256830: 'KAN_B',
           300034012388310: 'ZAK_T',
           300034012437350: 'ZAK_M',
           300034012699980: 'QAS_L',
           300034012776170: 'UPE_U',
           300034012931510: 'KPC_U',
           300034012932510: 'SCO_U',
           300034012934080: 'SCO_L',
           300234061218580: 'MIT',
           300234061218540: 'QAS_A',
           300234011039970: 'TAS_A',
           300234010884770: 'TAS_L',
           300034012930510: 'GEUS',
           300234061473490: 'CEN',
           300234065156620: 'DIS',
           300234065153530: 'THU_L (NEW)',
           300234065158630: 'THU_U (NEW)',
           300234065151610: 'SCO_L (NEW)',
           300234065157600: 'SCO_U (NEW)',
           300234065154530: 'QAS_M (NEW)',
           300034012712460: 'GEUS',
           300034012121000: 'GEUS',
           300234010718970: 'XXX',
           300034012719450: 'GEUS',
           300034012255830: 'GEUS',
           300034012259830: 'GEUS',
           300034013020180: 'GEUS',
           300234061299270: 'XXX',
           300034012200840: 'XXX',
           300034012200840: 'XXX',
           300034012779170: 'GEUS',
           }


def parse_declaration(norm_code):
    '''
    parse const and units declarations (not variables)
    '''
    
    name_value = norm_code.replace('const', '', 1).replace('units', '', 1)
    name, value = name_value.split('=', 1)
    return name.strip(), value.strip()


def parse_table_def(norm_code):
    '''
    parse table to extract its name, the variables names and averaging methods
    '''
    
    table_def = norm_code.replace('datatable', '', 1).strip('()')
    table_name, _ = table_def.split(',', 1)
    return table_name.strip()


def parse_table_var(norm_code, units):
    '''
    parse variable to extract its name, number format and averaging method
    '''
    
    fmt_vars_count = {'0': 3,  #Mean horizontal wind speed, unit vector mean wind direction, and standard deviation of wind direction
                      '1': 2,  #Mean horizontal wind speed and unit vector mean wind direction
                      '2': 4,  #Mean horizontal wind speed, resultant mean wind speed, resultant mean wind direction, and standard deviation of wind direction
                      '3': 1,  #Unit vector mean wind direction # WARNING: untested/unsupported
                      '4': 2,  #Unit vector mean wind direction and standard deviation of wind direction
                      }
    
    avg_meth, rest = norm_code.split('(', 1)
    avg_meth = avg_meth.strip()
    reps, var_name, params = rest.strip(' ()').split(',', 2)
    reps = int(reps)
    #print var_name
    
    if '(' in var_name:
        var_name, _ = var_name.strip(')').split('(', 1)

    if avg_meth == 'sample':
        var_type = params
        
    elif avg_meth == 'average':
        var_type, _ = params.split(',')
        
    if avg_meth == 'windvector':
        fmt = params[-1]
        vars_count = fmt_vars_count[fmt]
        if vars_count < 2: raise Warning('untested/unsupported var_count < 2')
        _, var_type, _ = params.split(',', 2)
        reps = reps * vars_count
    
    table_vars = OrderedDict()
    for n in range(1, reps+1):
        if reps > 1:
            name = '%s_%i' %(var_name, n)
        else:
            name = var_name
        if not var_name.endswith('dataterminator'):
            table_vars[name] = [avg_meth, var_type, units.get(name, '')]
        
    return table_vars


def parse_fieldnames(norm_code):
    '''
    parse FieldNames (the otional descriptions are not supported)
    '''
    
    names = norm_code.replace('fieldnames', '', 1).strip('(" )').split(',')
    
    return names

    
def parse_cr1(program):
    
    # for now it does not look at aliases so it can't always properly name 
    # variables and associate units. Also, turning everything lowercase for
    # ease of parsing alters the names of variables and units
    
    constants = {}
    units = {}
    tables = {}
    multiline = []
    
    with open(program) as pf:
        for ln, line in enumerate(pf):
            if "'" in line:
                code, comment = line.split("'", 1)
            else:
                code, comment = line, ''
            norm_code = code.strip().lower()  #CRBasic is case-insensitive
            
            if not multiline:
                if norm_code.startswith('const'):
                    constants.setdefault(*parse_declaration(norm_code))
                if norm_code.startswith('units'):
                    units.setdefault(*parse_declaration(norm_code))
                if norm_code.startswith('datatable'):
                    this_table_name = parse_table_def(norm_code)
                    print 'parsing', this_table_name, 'in', program
                    this_table_vars = OrderedDict()
                    multiline.append('table_def')
                    
            elif multiline[-1] == 'table_def':
                if norm_code.startswith('endtable'):
                    tables[this_table_name] = this_table_vars
                    this_table_name = None
                    this_table_vars = None
                    if multiline.pop() != 'table_def':
                        raise RuntimeError('parse error at line %i of %s'
                                           % (ln, p))
                elif any((norm_code.startswith('sample'),
                          norm_code.startswith('average'),
                          norm_code.startswith('windvector'))):
                    this_table_vars.update(parse_table_var(norm_code, units))
                elif norm_code.startswith('fieldnames'):
                    new_names = parse_fieldnames(norm_code)
                    old_names = this_table_vars.keys()[-len(new_names):]
                    for newn, oldn in zip(new_names, old_names):
                        this_table_vars[newn] = this_table_vars[oldn]
                        this_table_vars.pop(oldn)
                            
    binarytxformatid = int(constants['binarytxformatid'])
    return binarytxformatid, constants, units, tables


def build_headers(b, tables):
    
    msg_type = b % 5
    header = ''
    units = ''
    
    if msg_type == 0 or msg_type == 1:
        for tn in tables:
            if 'summer' or '60min'in tn.lower(): #it's always summer for Allan's 60 minutes
                header += ','.join(tables[tn].keys())
                units += ','.join(['%s (%s)' % (averaging, units) for
                                   averaging, vartype, units in
                                   tables[tn].values()])
                
    if msg_type == 2 or msg_type == 3:
        for tn in tables:
            if 'winter' in tn.lower():
                header += ','.join(tables[tn].keys())
                units += ','.join(['%s (%s)' % (averaging, units) for
                                               averaging, vartype, units in
                                               tables[tn].values()])
                
    if msg_type == 1 or msg_type == 3:
        for tn in tables:
            if 'instantaneous' in tn.lower():
                header += ','
                header += ','.join(tables[tn].keys())
                units += ','
                units += ','.join(['%s (%s)' % (averaging, units) for
                                               averaging, vartype, units in
                                               tables[tn].values()])

    if msg_type == 4:
        for tn in tables:
            if 'diagnostics' in tn.lower():
                header += ','.join(tables[tn].keys())
                units += ','.join(['%s (%s)' % (averaging, units) for
                                               averaging, vartype, units in
                                               tables[tn].values()])
                
    return '\n'.join((','.join((' timestamp', 'seconds_since_1990', header)),
                      ''.join(('-,', 'sec,', units)), 
                      ))  # space is for getting sorted at the top...


    
def parse_programs(programs_dir):
    
    headers = {}
    
    for p in programs_dir:
        binarytxformatid, constants, units, tables = parse_cr1(p)
        for b in range(binarytxformatid * 5, binarytxformatid * 5 + 5):
            if b in headers:
                continue  #raise Warning('format %i already known' %b)
            headers[b] = build_headers(b, tables)
            #print b, headers[b]
    
    return headers


#if __name__ == '__main__':
    
    #from pprint import pprint
    
    #programs_dir = glob('*.cr1')
    
    #sys.exit(parse_programs(programs_dir))




class IMAP4_TLS(imaplib.IMAP4_SSL):
    #Bring to the IMAP protocol some of the recent security improvements of
    #PEP 476, so this probably requires python 2.7.9 or even 2.7.10
    #It is perhaps still not validating the server certificate because it
    #requires an external library, so MITM is still possible.
    #
    #inspired to:
    # http://www.gossamer-threads.com/lists/python/python/1132087
    # http://blog.dornea.nu/2015/05/24/validating-and-pinning-x509-certificates


    def open(self, host, port):

        self.host = host
        self.port = port

        # Create new SSL context with most secure TLS v1.2
        # FIXME: Deprecated since version 2.7.13, use PROTOCOL_TLS | OP_NO_TLSv1_2 | OP_NO_TLSv1_1 | OP_NO_SSLv3 | OP_NO_SSLv2
        ssl_context = ssl.SSLContext(PROTOCOL_TLSv1_2)

        # Forbid downgrade to insecure SSLv2 nor SSLv3 (may be redundant)
        ssl_context.options |= ssl.OP_NO_SSLv2
        ssl_context.options |= ssl.OP_NO_SSLv3

        # Prevent CRIME and TIME attacks
        ssl_context.options |= ssl.OP_NO_COMPRESSION

        # Require that a server certificate is returned and is valid
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        ssl_context.verify_flags |= ssl.VERIFY_X509_STRICT
        #ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        #ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

        try:
            import certifi
        except ImportError:
            # load system certificates, not the best ones but always available
            ssl_context.load_default_certs()
            warnings.warn('certifi not installed, will use default system certificates')
        else:
            #load quality certificates if available (requires certifi library)
            ssl_context.load_verify_locations(certifi.where())

        #TODO: retrieve and load CRL as a PEM file (mostly useless anyways)
        #ssl_context.load_verify_locations(r"C:\Python27_64\Lib\test\revocation.crl")

        # Allow only good ciphers
        ssl_context.set_ciphers('HIGH:ECDHE:!aNULL:!RC4:!DSS')

        # Check host name
        ssl_context.check_hostname = True

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sslobj = ssl_context.wrap_socket(self.sock, server_hostname=host)
        self.sslobj.connect((host, port))

        #self.sock = socket.create_connection((host, port))
        #self.sslobj = ssl.wrap_socket(
            #self.sock,
            #self.keyfile,
            #self.certfile,
            #ssl_version=ssl_version,
        #)
        self.file = self.sslobj.makefile('rb')

if hack: 
    class IMAP4_TLS(imaplib.IMAP4): pass


class EmailMessageError(Exception): pass
class SbdMessageError(Exception): pass
class TrackerMessageError(Exception): pass
class AwsMessageError(Exception): pass
class NotEmailMessageError(ValueError): pass
class NotSbdMessageError(ValueError): pass
class NotTrackerMessageError(ValueError): pass
class NotAwsMessageError(ValueError): pass


class EmailMessage(object):

    def __init__(self, email_msg):
        self.validate_email(email_msg)
        self._email_msg = email_msg
        self.metadata = {} #this should be inherited from MimirObject
        self.metadata['email_metadata'] = NotImplemented
        self.data = {}
        self.data['email_data'] = self.parse_email()

    def validate_email(self, email_msg):
        if not isinstance(email_msg, email.message.Message):
            raise NotEmailMessageError

    def parse_email(self):
        email_data = {}
        email_data['from'] = self._email_msg.get_all('from')[0]
        email_data['to'] = self._email_msg.get_all('to')
        email_data['subject'] = self._email_msg.get_all('subject')[0]
        email_data['date'] = self._email_msg.get_all('date')[0]
        email_data['attached_filenames'] = []

        if self._email_msg.is_multipart():
            for part in self._email_msg.get_payload():
                fn = part.get_filename()
                if fn: email_data['attached_filenames'].append(fn)

        return email_data


class SbdMessage(EmailMessage):

    data_entries = {'MOMSN': 'momsn',
                   'MTMSN': 'mtmsn',
                   'Time of Session (UTC)': 'session_utc',
                   'Session Status': 'session_status',
                   'Message Size (bytes)': 'message_size',
                   'Unit Location': 'unit_location',
                   'CEPradius': 'cep_radius'
                   }

    data_decoders = {'MOMSN': '_parse_int',
                     'MTMSN': '_parse_int',
                     'Time of Session (UTC)': '_parse_str',
                     'Session Status': '_parse_session_status',
                     'Message Size (bytes)': '_parse_int',
                     'Unit Location': '_parse_unit_location',
                     'CEPradius': '_parse_int'
                     }

    def __init__(self, sbd):
        super(SbdMessage, self).__init__(sbd)
        self.validate_sbd(sbd)
        self.data['sbd_data'] = self.parse_sbd()
        #if self.data['sbd_data']['imei'] == 300234061852400: 
            #print '!'
        pass

    def validate_sbd(self, sbd):

        sender = self.data['email_data']['from']
        if 'sbdservice' not in sender and 'ice@geus.dk' not in sender:
            raise NotSbdMessageError("'sbdservice' not in %s" % sender)
        if len(self.data['email_data']['attached_filenames']) == 0:
            warnings.warn('sbd email %s %s has no *.sbd attachment' % (self.data['email_data']['date'],
                                                                       self.data['email_data']['subject']))
        for fn in self.data['email_data']['attached_filenames']:
            root, ext = os.path.splitext(fn)
            if ext != '.sbd':
                raise NotSbdMessageError("attachment %s not .sbd" % fn)


    def parse_sbd(self):

        if self._email_msg.is_multipart():
        #try:
            content, attachment = self._email_msg.get_payload()
            assert not content.is_multipart() #else the decode=True on the next line makes it return None and break the rest of the parsing
            body = content.get_payload(decode=True)
        else:
        #except ValueError:
            content = self._email_msg.get_payload(decode=True)#[0]
            attachment = None  #sometimes an email arrives with no .sbd attached
            body = content#.get_payload(decode=True)

        sbd_data = {}
        for line in body.splitlines():
            for key, entry in self.data_entries.items():
                if key in line:
                    decoder = getattr(self, self.data_decoders[key])
                    #decoder = partial(decoder, key, (': ', ' = '))
                    sbd_data[entry] = decoder(key, (': ', ' = '), line)

        imei, = re.findall(r'[0-9]+', self.data['email_data']['subject'])
        sbd_data['imei'] = imei

        if attachment != None:
            sbd_payload = attachment.get_payload(decode=True)
            assert len(sbd_payload) == sbd_data['message_size']
            sbd_data['payload'] = sbd_payload
        else:
            sbd_data['payload'] = None

        return sbd_data

    @staticmethod
    def _parse_int(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        return int(val)

    @staticmethod
    def _parse_str(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        return val

    @staticmethod
    def _parse_session_status(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        status = {}
        code, descr = val.split(' - ')
        status['code'], status['description'] = int(code), descr
        return status

    @staticmethod
    def _parse_unit_location(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        tokens = val.split()
        assert tokens[0].lower() == 'lat'
        assert tokens[3].lower() == 'long'
        location = {}
        location['lat'] = float(tokens[2])
        location['long'] = float(tokens[5])
        return location



class TrackerMessage(SbdMessage):

    payload_fmt = {0x06: '<BBBffHHHB',
                   0x86: '<BBBBffHHHB',
                   }

    def __init__(self, tracker_sbd):
        super(TrackerMessage, self).__init__(tracker_sbd)
        self.validate(tracker_sbd)
        self.data['tracker_data'] = self.parse_tracker()
        pass

    def validate(self, tracker_sbd):
        if self.data['sbd_data']['payload'] == None:
            raise NotAwsMessageError('no .sbd file attached to this SBD message')
        fmt = ord(self.data['sbd_data']['payload'][0])
        if fmt not in self.payload_fmt:
            raise NotTrackerMessageError("first byte '%' not in %s" %(fmt, self.payload_fmt.keys()))

    def parse_tracker(self, external=True):
        #external=True uses the sbdunpacker.exe tool so it won't work on the
        #linux server. But external=False is not yet implemented (the binary format is
        #understandable but messy

        tracker_data = {}
        understood = False

        if external:
            with open('temp.sbd', 'wb') as in_f:
                in_f.write(self.data['sbd_data']['payload'])
            output = sp.check_output('tracker_SBDUnpacker.exe temp.sbd') #TODO: exception handling
            voltage = -9999
            for l in output.splitlines():
                if l.startswith('Fix'):
                    understood = True
                    fixes = tracker_data.get('fixes', [])
                    fix = ','.join(l.replace(',', ' ').split()[2:])
                    fix = '%s,%s' %(fix, voltage)
                    fixes.append(fix)
                    tracker_data['fixes'] = fixes
                elif l.startswith('Input'):
                    understood = True
                    voltage = l.split()[-1]
                    voltage = float(voltage.replace('V', ''))
                    #print voltage
        else:
            raise NotImplementedError('tracker parser implementation is incomplete')
            #fmt = self.data['sbd_data']['payload'][0]
            #data = self.data['sbd_data']['payload'][1:]

            #tracker_data = {}
            #tracker_data['format'] = ord(fmt)

            #record_len = struct.calcsize(self.payload_fmt[tracker_data['format']])
            #records_count = len(data) / record_len
            #assert records_count % record_len == 0

        if not understood:
            raise TrackerMessageError('failed to decode message UID %s, permanently skipping it' %self.data['sbd_data']['imei'])
        if 'fixes' not in tracker_data:
            raise TrackerMessageError('message UID %s contains no fix, permanently skipping it' %self.data['sbd_data']['imei'])

        return tracker_data


FilterMalformed = True

#TODO: get all this config from the parsed CR-basic logger program, for now this is carried over 
# from the 2010 version speaking MAPI to the old GEUS Exchange server, look there for more comments

# *** START OF MESSAGE FORMAT SPECIFICATIONS FOR NORMAL USERS ***
# Here the format of the binary data is defined. The keys of the FormatSpec dictionary
# come in groups of 5 (5...9, 10...14, and so on) and each group corresponds to the set of
# messages that can be transmitted by a given AWS (summer, winter, diagnostic, ... see below)
# The BinaryTxFormatRevision setting in the logger program need to match with the keys
# of the FormatDict dictionary, so that BinaryTxFormatRevision = 1 corresponds to keys 5...9
# and BinaryTxFormatRevision = 5 to keys 25...29. This is required because the receiving
# end has no way to tell where and what kind of values are encoded in the binary message.
# The possible value types are as follow:
# f = value encoded as 2 bytes base-10 floating point (GFP2)
# l = value encoded as 4 bytes two's complement integer (GLI4)
# t = timestamp as seconds since 1990-01-01 00:00:00 +0000 encoded as GLI4
# g = GPS time encoded as GLI4
# n = GPS latitude encoded as GLI4
# e = GPS latitude encoded as GLI4
# It is also possible to decode any of these in debug mode which adds to the decoded value the 
# raw bytes as characters, as hex and as bit string, in brackets, e.g. an FP2 values of -1600 
# will be written out as -1600( @ = 0xE6 0x40 = 0b11100110 0b01000000) when using 'F' instead 
# of 'f'. Becasue no check is done, a line may get truncated if some special bytes are 
# encountered, probably things like null characters, end of line, escape codes etc. I'm also 
# not sure if/how differently it may work on python 3 or if the data file displays differently 
# based on the locale/character encoding set on the pc.

type_len = {'f': 2, # value encoded as 2 bytes base-10 floating point (GFP2)
            'l': 4, # value encoded as 4 bytes two's complement integer (GLI4)
            't': 4, # timestamp as seconds since 1990-01-01 00:00:00 +0000 encoded as GLI4
            'g': 4, # GPS time encoded as GLI4
            'n': 4, # GPS latitude encoded as GLI4
            'e': 4, # GPS latitude encoded as GLI4
            }

payload_fmt = { #Promice 2009, 2010 
                5: [13, "tffffffffffff", "Promice 2009 summer message"], #this means: expect 13 values: 1 of type 't' and 12 of type 'f', and display this as "Promice..."
                6: [39, "tfffffffffffffffffffffffffgneffffffffff", "Promice 2009 summer message (+ instant.)"],
                7: [13, "tffffffffffff", "Promice 2009 winter message"],
                8: [39, "tfffffffffffffffffffffffffgneffffffffff", "Promice 2009 winter message (+ instant.)"],
                9: [06, "tfffff", "Promice 2009 diagnostic message"],
                #GlacioBasis 2009 Main
                10: [49, "tfffffffffffffffffffffffffffffffffffgneffffffffff", "GlacioBasis 2009 Main 1-h summer message"],
                11: [56, "tfffffffffffffffffffffffffffffffffffgnefffffffffffffffff", "GlacioBasis 2009 Main 1-h summer message (+ instant.)"],
                12: [49, "tfffffffffffffffffffffffffffffffffffgneffffffffff", "GlacioBasis 2009 Main 3-h winter message"],
                13: [56, "tfffffffffffffffffffffffffffffffffffgnefffffffffffffffff", "GlacioBasis 2009 Main 3-h winter message (+ instant.)"],
                14: [22, "tfffffffffffffffffffff", "GlacioBasis 2009 Main diagnostic message"],
                #Quadra Mining2009
                15: [33, "tfffffffffffffffffffffffffgneffff", "Quadra 2009 3-h summer message"],
                16: [0, "", "unused"],
                17: [33, "tfffffffffffffffffffffffffgneffff", "Quadra 2009 24-h winter message"],
                18: [0, "", "unused"],
                19: [06, "tfffff", "Quadra 2009 diagnostic message"],
                #GlacioBasis 2009 Top
                20: [41, "tfffffffffffffffffffffffffffffffffgneffff", "GlacioBasis 2009 Top 1-h summer message"],
                21: [0, "", "unused"],
                22: [41, "tfffffffffffffffffffffffffffffffffgneffff", "GlacioBasis 2009 Top 6-h winter message"],
                23: [0, "", "unused"],
                24: [22, "tfffffffffffffffffffff", "GlacioBasis 2009 Top diagnostic message"],
                #Sermilik 2010 (corresponds to BinaryTxFormatRevision = 5 in the datalogger program)
                25: [13, "tffffffffffff", "Sermilik 2009 1-h summer message"],
                26: [39, "tfffffffffffffffffffffffffgneffffffffff", "Sermilik 2009 1-h summer message (+ instant.)"],
                27: [13, "tffffffffffff", "Sermilik 2009 6-h winter message"],
                28: [39, "tfffffffffffffffffffffffffgneffffffffff", "Sermilik 2009 6-h winter message (+ instant.)"],
                29: [06, "tfffff", "Sermilik 2009 diagnostic message"],
                #Promice 2015-
                30: [12, "tfffffffffff", "Promice 2015 summer message"], #there is 1 f less (wind variability)
                31: [37, "tffffffffffffffffffffffffgnefffffffff", "Promice 2015 summer message (+ instant.)"],#there are 2 f less (wind variability, wind var. instantaneous)
                32: [12, "tfffffffffff", "Promice 2015 winter message"], #there is 1 f less (wind variability)
                33: [37, "tffffffffffffffffffffffffgnefffffffff", "Promice 2015 winter message (+ instant.)"],#there are 2 f less (wind variability, wind var. instantaneous)
                34: [06, "tfffff", "Promice 2015 diagnostic message"],
                #Camp Century 2017-
                35: [53, "tffffffffffffffffffffffffffffffffffffffffffffffffffff", "Camp Century 2017 summer message"],
                36: [0, "", "no summer message (+ instant.)"],
                37: [53, "tffffffffffffffffffffffffffffffffffffffffffffffffffff", "Camp Century 2017 summer message"],
                38: [0, "", "no winter message (+ instant.)"],
                #GlacioBasis+DMI 2018
                40: [14, "tfffffffffffff", "GlacioBasis+DMI 2018 summer message"], #there is 2 more than promice 2015 (T_IR, IR_T)
                41: [39, "tffffffffffffffffffffffffffgnefffffffff", "GlacioBasis+DMI 2018 summer message (+ instant.)"],#there is 2 more than promice 2015 (T_IR, IR_T)
                42: [14, "tfffffffffffff", "GlacioBasis+DMI 2018 winter message"], #there is 2 more than promice 2015 (T_IR, IR_T)
                43: [39, "tffffffffffffffffffffffffffgnefffffffff", "GlacioBasis+DMI 2018 winter message (+ instant.)"],#there is 2 more than promice 2015 (T_IR, IR_T)
                44: [06, "tfffff", "GlacioBasis+DMI 2018 diagnostic message"],
                #placeholders for illegal format numbers (reserved for ascii decimal numbers, codes 48 for '0' to 57 for '9')
                48: [0, '', 'placeholder for uncompressed ascii'],
                49: [0, '', 'placeholder for uncompressed ascii'],
                50: [0, '', 'placeholder for uncompressed ascii'],
                51: [0, '', 'placeholder for uncompressed ascii'],
                52: [0, '', 'placeholder for uncompressed ascii'],
                53: [0, '', 'placeholder for uncompressed ascii'],
                54: [0, '', 'placeholder for uncompressed ascii'],
                55: [0, '', 'placeholder for uncompressed ascii'],
                56: [0, '', 'placeholder for uncompressed ascii'],
                57: [0, '', 'placeholder for uncompressed ascii'],
                #THIS IS THE FIRST UNUSED FORMAT (will match BinaryTxFormatRevision = 12 in the logger program)
                60: [1, "t", "new summer message"], #
                61: [1, "t", "new summer message (+ instant.)"],#
                62: [1, "t", "new winter message"], #
                63: [1, "t", "new winter message (+ instant.)"],#
                64: [1, "t", "new diagnostic message"],
                #THE VERSION-3
                #75: [38, "tfffffffffffFFfffgneffffffffffffffffff", 'THE VERSION-3!'], #note the debug FF letters for the sonic rangers
                #70: [37, "tffffffffffffffffffffffffgnefffffffff", 'THE VERSION-3!'], # New version 2020-01-23. note the debug FF letters for the sonic rangers
                75: [38, "tffffffffffffffffgneffffffffffffffffff", 'THE VERSION-3!'], #note the debug FF letters for the sonic rangers
                #75: [37, "tffffffffffffffffgneffffffffffffffffff", 'THE VERSION-3!'], #note the debug FF letters for the sonic rangers
                #80: [37, "tffffffffffffffffffffffffgnefffffffff", 'THE VERSION-3!'], # New version 2020-01-23. note the debug FF letters for the sonic rangers
                80: [40, "tfffffffffffffffffffffffffffffffffffffff", 'THE VERSION-3!'], # New version 2020-01-23. note the debug FF letters for the sonic rangers
                #ZAMG Freya aws
                220: [29, "tfffffffffffffffffffffffnefff", "ZAMG Freya 2015 summer message"],
                221: [0, "", ""],
                222: [29, "tfffffffffffffffffffffffnefff", "ZAMG Freya 2015 winter message"],
                223: [0, "", ""],
                224: [06, "tfffff", "ZAMG Freya 2015 diagnostic message"],
                }

for item in payload_fmt.items():
    key, val = item
    var_count, var_def, comment = val
    assert var_count == len(var_def)
    bytes_count = 0
    for var in var_def:
        bytes_count += type_len[var.lower()]
    payload_fmt[key].append(bytes_count + 1) #add the format byte


class AwsMessage(SbdMessage):

    def __init__(self, aws_sbd):
        
        super(AwsMessage, self).__init__(aws_sbd)

        self.payload_fmt, self.type_len = payload_fmt, type_len  #TODO: this must come from a YAML file

        # Win32 epoch is 1st Jan 1601 but MSC epoch is 1st Jan 1970 (MSDN gmtime docs), same as Unix epoch.
        # Neither Python nor ANSI-C explicitly specify any epoch but CPython relies on the underlying C
        # library. CRbasic instead has the SecsSince1990() function.
        UnixEpochOffset = calendar.timegm((1970, 1, 1, 0, 0, 0, 0, 1, 0)) #this should always evaluate to 0 in CPython on Win32, but anyways
        CRbasicEpochOffset = calendar.timegm((1990, 1, 1, 0, 0, 0, 0, 1, 0))
        self.EpochOffset = UnixEpochOffset + CRbasicEpochOffset

        self.validate(aws_sbd)
        self.data['aws_data'] = self.parse_aws() #TODO: when generalizing, 'aws_data' should not be hardcoded but come from some 'aws' label passed to the init or something.
        pass

    def validate(self, aws_sbd):
        if self.data['sbd_data']['payload'] == None:
            raise NotAwsMessageError('no .sbd file attached to this SBD message')
        fmt = ord(self.data['sbd_data']['payload'][0])
        if fmt not in self.payload_fmt:
            raise NotAwsMessageError('unrecognized first byte %s' %hex(ord(self.data['sbd_data']['payload'][0])))

    def parse_aws(self, external=True):

        aws_data = {}

        payload = self.data['sbd_data']['payload']

        #============== adapted from old, should be cleaned up =========================================
        DataLine = payload

        IsTooLong = False
        IsTooShort = False
        if len(DataLine) == 0: raise AwsMessageError()
        if DataLine[0].isdigit() or (DataLine[0:2] == '\n"' and #special-case hack for CENT_T in 2017-2018
                                     self.data['sbd_data']['imei'] == 300234064121930):
            IsKnownBinaryFormat = False
            MessageFormatNum = -9999
        else:
            MessageFormatNum = ord(DataLine[0])
            try:
                MessageFormat = self.payload_fmt[MessageFormatNum]
                IsKnownBinaryFormat = True
            except KeyError:
                IsKnownBinaryFormat = False
                UnknMsgFormNum = MessageFormatNum
            if IsKnownBinaryFormat:
                print '%s-%s (binary)' %(self.data['sbd_data']['imei'], self.data['sbd_data']['momsn']) , MessageFormat[2]
                ExpectedMsgLen = MessageFormat[3]
                BinaryMessage = DataLine[1:]
                DataLine = ''
                BytePointer = 0
                ValueBytes = []
                for ValueNum in range(0, MessageFormat[0]):
                    
                    if ValueBytes: #means we have just parsed a value so if needed add debug an always add a comma
                        if type_letter.isupper(): #then it's meant for adding debug output
                            DataLine = DataLine + self.RAWtoSTR(ValueBytes)
                        DataLine = DataLine + ','
                        ValueBytes = []
                        
                    type_letter = MessageFormat[1][ValueNum]
                    ValueBytesCount = self.type_len[type_letter.lower()]
                    
                    if type_letter.lower() == 'f':
                        try:
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GFP2toDEC(ValueBytes)
                            if Value == 8191:
                                DataLine = DataLine + "NAN"
                            elif Value == 8190:
                                DataLine = DataLine + "INF"
                            elif Value == -8190 or Value == -8191: #so, which one is correct?
                                DataLine = DataLine + "-INF"
                            else:
                                DataLine = DataLine + str(Value)
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'l':
                        try:
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value)
                            if Value in (-2147483648, 2147450879):
                                DataLine = DataLine + "NAN"
                            else:
                                DataLine = DataLine + str(Value)
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 't':
                        try:
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(Value + self.EpochOffset)) + ',' + str(Value)
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'g':
                        try:
                            for offset in range(0,2):                                
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            if self.GFP2toDEC(ValueBytes) == 8191: #the logger sends a 2-bytes NAN instead of a 4-bytes gps values when the gps data isn't available
                                DataLine = DataLine + "NAN,"
                                BytePointer = BytePointer + 2
                                ExpectedMsgLen -= 2 #this is to fix the expected length of the message which is shorter when 2-bytes NAN come in instead of 4-byte gps values
                                continue
                            else:
                                ValueBytes = []
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value/100.0)
                            #else:
                                #DataLine = DataLine + "NAN"
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'n':
                        try:
                            for offset in range(0,2):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            if self.GFP2toDEC(ValueBytes) == 8191: #the logger sends a 2-bytes NAN instead of a 4-bytes gps values when the gps data isn't available
                                DataLine = DataLine + "NAN,"
                                BytePointer = BytePointer + 2
                                ExpectedMsgLen -= 2 #this is to fix the expected length of the message which is shorter when 2-bytes NAN come in instead of 4-byte gps values
                                continue
                            else:
                                ValueBytes = []
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value/100000.0)
                            #else:
                                #DataLine = DataLine + "NAN"
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'e':
                        try:
                            for offset in range(0,2):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            if self.GFP2toDEC(ValueBytes) == 8191: #the logger sends a 2-bytes NAN instead of a 4-bytes gps values when the gps data isn't available
                                DataLine = DataLine + "NAN,"
                                BytePointer = BytePointer + 2
                                ExpectedMsgLen -= 2 #this is to fix the expected length of the message which is shorter when 2-bytes NAN come in instead of 4-byte gps values
                                continue
                            else:
                                ValueBytes = []
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value/100000.0)
                            #else:
                                #DataLine = DataLine + "NAN"
                        except IndexError:
                            DataLine = DataLine + '?'
                    #if type_letter.isupper(): #then it's meant for adding debug output
                        #DataLine = DataLine + self.RAWtoSTR(ValueBytes)
                    #DataLine = DataLine + ','
                #DataLine = DataLine[:-1] # to remove the trailing comma character
        IsDiagnostics = '!D' in DataLine[-5:-3] or MessageFormatNum % 5 == 4#FIXME: the stats are wrong because we don't always go through here
        IsObservations = '!M' in DataLine[-2:] or IsKnownBinaryFormat
        IsSummer = ('!S' in DataLine and '!M' in DataLine[-2:]) or MessageFormatNum % 5 in (0, 1)
        IsWinter = ('!W' in DataLine and '!M' in DataLine[-2:]) or MessageFormatNum % 5 in (2, 3)
        IsWithInstant = '!I' in DataLine[-5:-3] or (MessageFormatNum % 5 in (1, 3) and MessageFormatNum != -9999)
        if not IsKnownBinaryFormat:
            print '%s-%s' %(self.data['sbd_data']['imei'], self.data['sbd_data']['momsn']),
            if IsDiagnostics: print '(ascii) generic diagnostic message',
            elif IsObservations and IsSummer:print '(ascii) generic summer observations message',
            elif IsObservations and not IsSummer: print '(ascii) generic winter observations message',
            else: print 'unrecognized message format',
            if IsWithInstant:
                print '(+ instant.)'
            else:
                print ''
        else:
            if len(BinaryMessage)+1 < ExpectedMsgLen:
                IsTooShort = True
            elif len(BinaryMessage)+1 > ExpectedMsgLen:
                IsTooLong = True
                
        IsMalformed = IsTooLong or IsTooShort
        if IsMalformed:
            print (''.join((chr(MessageFormatNum), BinaryMessage))).decode('cp850')
            print "  WARNING - Message malformed: expected %i bytes, found %i" %(ExpectedMsgLen, len(BinaryMessage)+1)
            print "            if binary, missing values replaced by '?' and extra values dropped"
    
        if IsMalformed and FilterMalformed:
            flag = '-F'
        elif IsDiagnostics:
            flag = '-D'
        elif IsObservations:
            flag = ''
        else: #if not diagnostics nor a properly terminated message or known binary format, then it's garbage and gets dumped here
            flag = '-X'
        
        aws_data['firstbyte_fmt'] = MessageFormatNum
        aws_data['decoded_string'] = DataLine
        aws_data['flag'] = flag
        return aws_data

    @staticmethod
    def GFP2toDEC(Bytes):
        msb = Bytes[0]
        lsb = Bytes[1]
        Csign = -2*(msb & 128)/128 + 1
        CexpM = (msb & 64)/64
        CexpL = (msb & 32)/32
        Cexp = 2*CexpM + CexpL - 3
        Cuppmant = 4096*(msb & 16)/16 + 2048*(msb & 8)/8 + 1024*(msb & 4)/4 + 512*(msb & 2)/2 + 256*(msb & 1)
        Cnum = Csign * (Cuppmant + lsb)*10**Cexp
        return Cnum

    @staticmethod
    def GLI4toDEC(Bytes):
        Csign = -2 * (Bytes[0] & 0x80) / 0x80 + 1
        byte1 = Bytes[0] & 127
        byte2 = Bytes[1]
        byte3 = Bytes[2]
        byte4 = Bytes[3]
        return Csign * byte1 * 0x01000000 + byte2 * 0x010000 + byte3 * 0x0100 + byte4
    
    @staticmethod
    def RAWtoSTR(Bytes):
        us = [unichr(byte) for byte in Bytes] #the unicode strings
        hs = ['0x{0:02X}'.format(byte) for byte in Bytes] #the hex strings
        bs = ['0b{0:08b}'.format(byte) for byte in Bytes] #the bit strings
        return '(%s = %s = %s)' %(' '.join(us), ' '.join(hs), ' '.join(bs))


def connect(host, port, user, passw):

    assert ssl.RAND_status()

    mail_server = IMAP4_TLS(host, port)

    # verify TLS is allright before disclosing login credentials
    if not hack:
        context = mail_server.ssl().context
        assert context.check_hostname
        ssl.match_hostname(mail_server.sslobj.getpeercert(), host)

    mail_server.login(user, passw)

    return mail_server


def new_mail(mail_server, last_uid=1):

    # issue the search command of the form "SEARCH UID 42:*"
    command = '(UID {}:*)'.format(last_uid)
    result, data = mail_server.uid('search', None, command)
    messages = data[0].split()
    print 'new UIDs: %s' %data[0]

    # yield mails
    for message_uid in messages:
        # SEARCH command *always* returns at least the most
        # recent message, even if it has already been synced
        if int(message_uid) > last_uid:
            print 'fetching', message_uid
            result, data = mail_server.uid('fetch', message_uid, '(RFC822)')
            # yield raw mail body
            yield message_uid, data[0][1]


def publish_to_ftp(filename, host, user, passwd, acct='', path='.', passive=True):
    
    for fn in glob(filename):
        
        print 'publishing', filename, 'to', '/'.join((host, path))
        
        remote_fn = os.path.basename(fn)
        subdirs = path.split('/')
        
        try:
            
            ftp = ftplib.FTP(host, user, passwd, acct)
            ftp.set_pasv(passive)
        
            if path != '.':
                for dirname in subdirs:
                    try:
                        ftp.cwd(dirname)
                    except ftplib.error_perm, e:
                        ftp.mkd(dirname)
                        ftp.cwd(dirname)
            
            with open(fn, 'rb') as f_in:
                ftp.storbinary('STOR %s' %remote_fn, f_in)
        except Exception, e:
            raise e
              
        else:
            ftp.close()
    
    
def getmytrackerdata(account=None, password=None, server='imap.gmail.com', port=993):
    
    print 'GPS data from server %s, account %s' %(server, account)
    
    account = account or raw_input('account: ')
    password = password or raw_input('password: ')
    server = server or raw_input('server: ')
    port = port or raw_input('port: ')

    out_dir = os.sep.join(('..', 'tracker_data'))
    
    try:
        with open('last_tracker_uid.ini', 'r') as last_uid_f:
            last_uid = int(last_uid_f.readline())
    except Exception:
        last_uid = 1
    
    try:
        mail_server = connect(server, port, account, password)
    
        #resp = mail_server.list()
        #assert resp[0].upper() == 'OK'
    
        result, data = mail_server.select(mailbox='INBOX', readonly=True)
        print 'mailbox contains %s messages' %data[0]
    
        modified_files = set() # FIXME: sorter now expects a dict, not a set, so this errors later on

        for uid, mail in new_mail(mail_server, last_uid=last_uid):
    
            message = email.message_from_string(mail)
            try:
                tracker_msg = TrackerMessage(message)
            except (ValueError, TrackerMessageError), e:
                print e.message
                with open('last_tracker_uid.ini', 'w') as last_uid_f:
                    last_uid_f.write(uid)
                continue
    
            #remembering the uid allows skipping messages certainly done already,
            #but a crash between the data save and the update of last_uid will
            #result in duplicating the last message (i.e., this does not replace
            #duplicate checking before parsing/appending, which is still TODO)
    
            out_fn = 'TRACKER_%s.txt' %tracker_msg.data['sbd_data']['imei']
            out_path = os.sep.join((out_dir, out_fn))

            modified_files.add(out_path)
            
            with open(out_path, mode='a') as out_f:
                for fix in tracker_msg.data['tracker_data']['fixes']:
                    out_f.write('%s\n' %fix)
    
            with open('last_tracker_uid.ini', 'w') as last_uid_f:
                last_uid_f.write(uid)

        sorter(modified_files)
                
    except Exception, e:
        traceback.print_exc(file=sys.stdout)
        #print e
        
    finally:
        if 'mail_server' in locals():
            print 'closing', account
            mail_server.close()
            resp = mail_server.logout()
            assert resp[0].upper() == 'BYE'


def getmyawsdata(account=None, 
                 password=None, 
                 server='imap.gmail.com' if not hack else 'promice.citterio.net', 
                 port=993 if not hack else 3993,
                 ):
    
    programs = glob(os.sep.join((programs_dir, '*.cr1')))
    print 'parsing %s for message formats' %', '.join(programs)
    
    #for p in programs:
    headers = parse_programs(glob(os.sep.join((programs_dir, '*.cr1*'))))
    print "found definitions for %s 'first byte' formats" %', '.join([str(k) for k in sorted(headers.keys())])
    print 'AWS data from server %s, account %s' %(server, account)
    
    account = account or raw_input('account: ')
    password = password or raw_input('password: ')
    server = server or raw_input('server: ')
    port = port or raw_input('port: ')
    
    out_dir = os.sep.join(('..', 'aws_data'))

    try:
        with open('last_aws_uid.hack.ini' if hack else 'last_aws_uid.ini', 'r') as last_uid_f:
            last_uid = int(last_uid_f.readline())
    except Exception:
        last_uid = int(raw_input('last_aws_uid.ini not found, first UID? (deafult = 1)') or 1)

    try:
        mail_server = connect(server, port, account, password)

        #resp = mail_server.list()
        #assert resp[0].upper() == 'OK'
    
        result, data = mail_server.select(mailbox='[Gmail]/All Mail', readonly=True)
        print 'mailbox contains %s messages' %data[0]
        
        modified_files = {}
    
        for uid, mail in new_mail(mail_server, last_uid=last_uid):
    
            message = email.message_from_string(mail)
            
            try:
                aws_msg = AwsMessage(message)
            except ValueError, e:
                print e
                continue
            
            if hack: print aws_msg.data['sbd_data']['imei']
            
            #if aws_msg.data['sbd_data']['imei'] != 300234061852400: continue
        
            #remembering the uid allows skipping messages certainly done already,
            #but a crash between the data save and the update of last_uid will
            #result in duplicating the last message (i.e., this does not replace
            #duplicate checking before parsing/appending, which is still TODO)
    
            out_fn = 'AWS_%s%s.txt' % (aws_msg.data['sbd_data']['imei'],
                                       aws_msg.data['aws_data']['flag'])
            out_path = os.sep.join((out_dir, out_fn))
            
            aws_name = imei_names.get(aws_msg.data['sbd_data']['imei'], 'UNKNOWN')
            
            #write_header = out_path not in  modified_files.keys()
            #
            modified_files[out_path] = [aws_name, 
                                        '%s' % headers.get(aws_msg.data['aws_data']['firstbyte_fmt'], '')]
    
            with open(out_path, mode='a') as out_f:
                out_f.write('%s\n' %aws_msg.data['aws_data']['decoded_string'].encode('Latin-1'))
                #if write_header:
                    #out_f.write('%s\n' % headers.get(aws_msg.data['aws_data']['firstbyte_fmt'], ''))
    
            with open('last_aws_uid.hack.ini' if hack else 'last_aws_uid.ini', 'w') as last_uid_f:
                last_uid_f.write(uid)

        #if hack:
            #sorter(glob.glob(os.sep.join((out_dir, 'AWS*.txt'))))
        #else:
            #sorter(modified_files)
            
    except Exception, e:
        traceback.print_exc(file=sys.stdout)
        #print e
        
    finally:
        if 'mail_server' in locals():
            print 'closing', account
            mail_server.close()
            resp = mail_server.logout()
            assert resp[0].upper() == 'BYE'
    
    return modified_files



class LockFile(object): #TODO: could this be nicer to use as a context manager?
    
    def __init__(self, file_path='lock.txt', acquire_later=False):
        
        self.file_path = file_path
        self.lock = None
        if not acquire_later:
            self.acquire()
                  
    
    def _create_lock_file(self, file_path):
        lock = open(file_path, 'w')
        lock.write('%s owns or last owned the lock. This file is used to prevent more than one instance of the program\n'
                   'from running at the same time, which would screw up the output files. Just ignore it.'% getpass.getuser())
        lock.flush()
        return lock
    
    
    def acquire(self):
        #This is not 100.00% reliable but is good enough. The catch being that someone else may create the lock 
        #file just after open(file_path, 'r') failed for not finding it but before we manage to create it ourselves.
        #When this happens, we both end up owning the same lock (because creating a file doesn't fail if it exists).
        #However fixing this cross platform and on a network share is too much effort.
        
        try:
            open(self.file_path, 'r')
        except IOError:
            self.lock = self._create_lock_file(self.file_path)
            return True
        else:
            try:
                os.remove(self.file_path)
            except OSError:
                raise RuntimeError('lock %s already taken' %self.file_path)
            else:
                self.lock = self._create_lock_file(self.file_path)
                return True
    
    
    def release(self):
        if self.lock:
            self.lock.close()
            os.remove(self.file_path)
        return True



def main(argv):
    
    # periodically fetch data, should be rewritten to get all it needs from the ini files 
    
    #print os.getcwd()
    
    interval = True
    
    try:
        lock = LockFile()

    except RuntimeError, e:
        print e
        print "somebody is already running this on the same directory, you can't nor need to"
        raw_input()
        
    else:
        print 'will fetch data every %i seconds' %interval
        
        password_aws = accounts_ini.get('aws', 'password')
        if not password_aws:
            password_aws = raw_input('password for AWS email account: ')
            
        password_trackers = accounts_ini.get('trackers', 'password')
        if not password_trackers:
            password_trackers = raw_input('password for trackers email account: ')
            
        password_zamg_ftp = accounts_ini.get('zamg_ftp', 'password')
        if not password_zamg_ftp:
            password_zamg_ftp = raw_input('password for zamg ftp account: ')
            
        password_uwn_ftp = accounts_ini.get('uwn_ftp', 'password')
        if not password_uwn_ftp:
            password_uwn_ftp = raw_input('password for Uni. West Norway ftp account: ')
            
        if interval:
            try:
                modified_files = getmyawsdata(accounts_ini.get('aws', 'account'),
                                              password_aws,
                                              accounts_ini.get('aws', 'server'),
                                              accounts_ini.getint('aws', 'port'),
                                              )
                sorter(modified_files)
                tailer(modified_files, 100, 'tails')
                
                #publish_to_ftp(r"O:\AWSmessages_current\aws_data\AWS_300234061852400.txt",
                               #'ftp.geus.dk',
                               #'geus',
                               #'geus',
                               #path='geus/mcit/to_ZAMG_Vienna',
                               #)
                publish_to_ftp(r"O:\AWSmessages_current\aws_data\AWS_300234061852400.txt",
                               accounts_ini.get('zamg_ftp', 'server'),
                               accounts_ini.get('zamg_ftp', 'account'),
                               password_zamg_ftp,
                               path=accounts_ini.get('zamg_ftp', 'directory'),
                               )
                publish_to_ftp(r"O:\AWSmessages_current\aws_data\AWS_300234061217540.txt",
                               accounts_ini.get('uwn_ftp', 'server'),
                               accounts_ini.get('uwn_ftp', 'account'),
                               password_uwn_ftp,
                               passive=False, # move to ini file
                               )
                #publish_to_ftp(r"O:\AWSmessages_current\aws_data\AWS_300234064121930*.txt",
                               #'ftp.geus.dk',
                               #'geus',
                               #'geus',
                               #path='geus/mcit/CC_testing',
                               #)
                #publish_to_ftp(r"O:\AWSmessages_current\aws_data\AWS_300234061217540*.txt",
                               #'ftp.geus.dk',
                               #'geus',
                               #'geus',
                               #path='geus/mcit/to_HISF',
                               #)
                #publish_to_ftp(r"O:\AWSmessages_current\aws_data\AWS_300234061299270.txt",
                               #'ftp.geus.dk',
                               #'geus',
                               #'geus',
                               #path='geus/mcit/to_GlacioBasis_Nuuk',
                               #)
                all_aws_tails = glob('\\\\geusnt1\\glaciologi\\AWSmessages_current\\aws_data\\tails\\*.txt')
                exclude_patterns = ['-F.txt',
                                    '-D.txt',
                                    'UWN_AWS',
                                    'ZAMG_AWS',
                                    'NUK_K_AWS',
                                    'XXX_AWS',
                                    'ZAK_'] # FIXME: why were these excluded?
                for t in all_aws_tails:
                    if any(map(t.count, exclude_patterns)):
                        continue
                    else:
                        publish_to_ftp(t,
                                       accounts_ini.get('dmi_ftp', 'server'),
                                       accounts_ini.get('dmi_ftp', 'account'),
                                       accounts_ini.get('dmi_ftp', 'password'),
                                       #path='from_GEUS',
                                       )
                
                
               # if not hack: getmytrackerdata(accounts_ini.get('trackers', 'account'),
               #                               password_trackers,
               #                               accounts_ini.get('trackers', 'server'),
               #                               accounts_ini.getint('trackers', 'port'),
               #                               )
            except Exception, e:
                traceback.print_exc(file=sys.stdout)
                print time.asctime(), '- restarting in 5 minutes...'
#                time.sleep(300)
            else:
                print 'latest data check:', time.asctime()
#                time.sleep(interval)
        
    finally: #still skipped if shell or process are killed
        lock.release()


if __name__ == '__main__':
    import sys
    print 'python', sys.version
    print sys.executable
    print os.getcwdu()
    sys.exit(main(sys.argv))
