"""
@author: Mohammad Kajbaf
@date: 2015-05-25
@revision: 3

Migrate data from IFS ERP to ActiveDirectory and CA Directory to initialize customized CA IDM.
Verify data consistency between 3 systems to find direct changes in ActiveDirectory or CA Directory regarding IFS ERP.
Applies corrections on mismatched data - ONLY AFTER official communication with related parties - Security Team.
Employs django models / sqlite to store data.
Logs any inconsistencies between data.
"""
## Imports
import sys
import os
import ldap
import ldap.modlist as modlist
import ldif
import sys
import time
from kajlib import automain, warning, error, path, getstr
import kajlib
import getpass
import unittest
import argparse
import csv
import tempfile
from LDAPHelper import *
import handle_ldap
import django
import fnmatch
from datetime import datetime, timedelta, date
from time import time
import logging

## Constants
svc_user = 'uuuuuu'
svc_password = r'pppppp'
server = 'sssssss.ir'

_root = kajlib.path(os.path.join(os.path.dirname(os.path.realpath(__file__)),'files'))

file_pat = r'IFS_CSV -%s.csv'
get_file_date = lambda _file: str(_file).split('\\')[-1].split('.')[0].split(' -')[-1]
get_ps_uid = lambda user_dn: user_dn.split(',')[0].split('=')[1]
ext_pat = '*.csv'
date_pat = r'%Y-%m-%d'
uid_pat = 'PERSON_ID'
ifs_mngr_att = 'MANAGER_PERSON_ID'
ad_mngr_att = 'manager'
ps_state_att = 'eTCustomField09'
ps_mngr_att = 'eTCustomField11'
ps_dn_fmt = 'eTGlobalUserName=%s,eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta'

## Macros

#NIL = 'nil'
#is_nil = lambda x: x == NIL
is_nil = lambda x: not bool(x)
night, all, early = 'night', 'all', date(2015, 6, 1)
getDate = lambda sDate: datetime.now().date() - timedelta(days=1) if night.startswith(sDate) else early if all.startswith(sDate) else datetime.strptime(sDate, date_pat).date()

## Init django model
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
#os.environ.setdefault("DJANGO_SETTINGS_MODULE", "IFS_Sync.settings")
from sync_model.models import *

## Initialize parser / logger

def parse_args(argv=None):
    """
    parses arguments
    """
    parser = argparse.ArgumentParser(prog='IFS_Sync', description='A script to process and compare sync files'
                                                 'and elicit mismatches', add_help=True)

#    action = parser.add_argument_group('Action Options', 'Activity to be performed and its criteria')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='run debugging mode')
    i_action = parser.add_argument_group('Import Options')
    parser.add_argument('-i', '--import-data', action='store_true', default=False, help='imports data into database from date --old-date')
    i_action.add_argument('-r','--root', help='root folder for csv files', type=kajlib.path, default=_root, metavar='folder')

    parser.add_argument('-v', '--verify', action='store_true', default=False, help='verifies data in database. If data is being imported, only the imported data is checked')
    v_action = parser.add_argument_group('Verify Options', 'Credentials used for verification of user attributes')
#    cred_ro = v_action.add_argument_group('username / passwd'
    v_action.add_argument('-u','--username', help='username for base directory')
    v_action.add_argument('-p','--password', help='password for base directory')
    
    apply = parser.add_argument('-a', '--apply', action='store_true', default=False, help='applies modified data in database. If data is imported, only the imported data is being applied')
    a_action = parser.add_argument_group('Apply Options', 'Credentials used for applying patches to ActiveDirectory data')
#    cred_svc = a_action.add_argument_group('Update', )
    a_action.add_argument('-s','--ad-service', help='username for active directory', metavar='service account')
    a_action.add_argument('-c','--ad-credentials', help='password for active directory', metavar='service credentials')

    parser.add_argument('-o','--old-date', default='night', nargs='?', type=getDate,
                    help='[yyyy-MM-dd | night | all] date to go back in processing data; '
                    'default: ''-o %(default)s or omit [-o] option to process last night data;'
                    ' -o all to process all the data after 2015-06-01; ',
                    metavar='date')
    parser.add_argument('-f', '--sync-fields', metavar='attrib', dest='attribs', default=['MANAGER_PERSON_ID'], nargs='+', 
                        help='provide a space seperated list of attributes', type=str.upper)   

    args = {}
    if argv:
        args = parser.parse_args(argv)
    else:
        args = parser.parse_args()
    
    if args.import_data:
        if not args.username:
            username = getpass.getuser()
            if '@' in username:
                username = username.split('@')[0]
            elif '\\' in username:
                username = username.split('\\')[-1]
            _username = kajlib.getstr('Enter username [default: %s] '%username)
            if _username:
                username = _username
            args.username = username
        if args.password is None:
            args.password = getpass.getpass()
    if args.apply:
        if not args.ad_service:
            args.ad_service = svc_user
        if not args.ad_credentials:
            args.ad_credentials = svc_password
#        if not args.ad_service or not args.ad_credentials:
#            raise argparse.ArgumentError(apply, 'requires ad-service/ad-credentials to be provided')

#    if args.root:
#        root = kajlib.path(args.root)
#    if not args.old_date:
#        args.old_date = '2015-11-01'
    global debug
    debug = args.debug
    if debug:
        print args
    return args

def getLogger(root, name=__name__):
    logger = logging.Logger(name)
    _log_file = root / 'sync.log'
    _log_file_handle = logging.FileHandler(_log_file.target)
    _log_file_handle.setLevel(logging.INFO)
    _log_file_handle.setFormatter(logging.Formatter('%(levelname)s %(asctime)s %(module)s %(message)s'))
    logger.addHandler(_log_file_handle)
    _stream_handle = logging.StreamHandler()
    _stream_handle.setLevel(logging.DEBUG)
    logger.addHandler(_stream_handle)
    return logger

## Handle files
	
def read_file(f):
    _res = []
    with f.open() as _f:
        r = csv.DictReader(_f)
        for row in r:
            try:
                row.pop('')
            except:
                pass
            _res.append(row)
    return _res

def list_files(root, start_date):
    _res = []
    _list = fnmatch.filter(os.listdir(root.target), ext_pat)
    _list.sort()
##    _list.reverse()
    file_old = file_pat % (start_date.strftime(date_pat))
    for _f in _list:
        if _f < file_old:
            log.info('skipping file %s', _f)
            continue
        f = root / _f
        if f.isfile():
            _res.append(f)
    return _res

## Handle data

def save_data(data, date):
    get_user = lambda uid: user_data.objects.filter(uid=uid)
    str_date = date.strftime(date_pat)
    for d in data:
        uid = d[uid_pat].lower()
        u = get_user(uid)
        if u:
            log.info('%s already exits', uid)
            u = u[0]
            if u.date > date.date():
                log.info('%s: skipping a more updated version', (u.date.strftime(date_pat)))
            if u.date >= date.date():
                continue
        else:
            u = user_data(uid=uid)
        u.piggy_bak(str_date)
        log.info('...updating data for %s', uid)
        u.set_attrs(d)
        u.date = date 
        u.save()

def import_data(args):
    date_old = args.old_date
    files = list_files(args.root, date_old)
    for f in files:
        try:
            f_date = datetime.strptime(get_file_date(f), date_pat)
        except:
            log.error('error processing files %s, bypassed', f)
            continue
        log.info('\n\tProcessing date %s ... ', get_file_date(f))
        data = read_file(f)
        save_data(data, f_date)

def verify(args):
    is_disabled = lambda state: state.upper() == 'DIS'
    all_users = {}
    try:
        _u_bak, handle_ldap.data.user = handle_ldap.data.user, args.username
        _p_bak, handle_ldap.data.passwd = handle_ldap.data.passwd, args.password
        with handle_ldap.login_ps() as l_ps, handle_ldap.login_active() as l_ad:
            i = 0
            for u in user_data.objects.filter(date__gte=args.old_date):
                i += 1
                if i % 100 == 0:
                    log.info('\n... verified %d' , i)
                uid = u.uid
                _q1 = LDAPQuery() & { Helper.PSUser.name: uid}
                try:
                    _u1 = handle_ldap.search_ldap(l_ps, _q1.string, Helper.PSUser._root, attributes=[ps_state_att, ps_mngr_att])
                    if _u1:
                        _u1 = _u1[0]
                        u.state = _u1[ps_state_att]
                        if debug:
                            log.debug('PS State: %s, Manager: %s', u.state, get_ps_uid(_u1.get(ps_mngr_att)))
                        if is_disabled(u.state):
                            log.info('bypassing %s user %s', u.state, uid)
                            u.save()
                            continue
                except:
                    pass

                _q2 = LDAPQuery() & { Helper.ADUser.name: uid}
                _u2 = handle_ldap.search_ldap(l_ad, _q2.string, Helper.ADUser._root, attributes=[Helper.ADUser.manager])
                try:
                    if _u2:
                        _u2 = _u2[0]
                        u.ad_manager = _u2[Helper.ADUser.manager]
                        if debug:
                            log.debug('AD manager: %s', get_ps_uid(u.ad_manager))
                except:
                    pass
                u.save()
                all_users[uid] = {'db':u, 'ps':_u1, 'ad':_u2}
                if not is_nil(u.ad_manager):
                    _um = handle_ldap.search_ldap(l_ad, '(objectClass=*)', u.ad_manager, ldap.SCOPE_BASE, attributes=[Helper.ADUser.name])
    #                print _um
                    if _um:
                        _um = _um[0]
                    if _um:
                        ad_manager_id = _um.get(Helper.ADUser.name).lower()
                    else:
                        log.error('%s ActiveDirectory manager was not retrieved: %s', uid, u.ad_manager)
                    mid = u.get_attrs(ifs_mngr_att).lower()
                    if mid == "a.dezfouli":
                        mid = "dezfouli"
                    all_users[uid]['mid'] = mid
                    if ad_manager_id != mid:
                        log.error('\n!!! Mismatch\n\t%s\t AD: %s -> %s', uid, ad_manager_id, mid)
                        all_users[uid]['err'] = True
    finally:
        handle_ldap.data.user = _u_bak
        handle_ldap.data.passwd = _p_bak
    return all_users

def apply(all_users, args):
    try:
        _u_bak, handle_ldap.data.user = handle_ldap.data.user, args.username
        _p_bak, handle_ldap.data.passwd = handle_ldap.data.passwd, args.password
        with handle_ldap.login_ps() as l_ps, handle_ldap.login_active() as l_ad:
            handle_ldap.data.user = args.ad_service
            handle_ldap.data.passwd = args.ad_credentials
            with handle_ldap.login_active() as l_svc:
                for uid in all_users:
                    if all_users[uid].get('err'):
                        if all_users[uid]['db'].state == 'DIS':
                            log.info('user %s is %s', uid, all_users[uid]['db'].state)
                            continue
                        mid = all_users[uid]['mid']
                        log.debug('uid %-20s: set correct manager %s', uid, mid)
                        if mid:
                            _q = LDAPQuery(**{Helper.ADUser.name: all_users[uid]['mid']})
                            _ucm = handle_ldap.search_ldap(l_ad, _q.string, Helper.ADUser._root, attributes=[Helper.ADUser.name])
                            if not _ucm:
                                log.error('ActiveDirectory does not contain the manager for %s   ==>>  %s', uid, all_users[uid]['mid'])
                                continue
                            _ucm = _ucm[0]
                        else:
                            _ucm = {}
                        if debug:
                            log.debug(all_users[uid])
                        if mid:
                            ps_manager_dn = ps_dn_fmt % str(mid)
                        else:
                            ps_manager_dn = ""
                        _mod1 = [ ( ldap.MOD_REPLACE, ps_mngr_att, ps_manager_dn) ]
                        if debug:
                            log.debug("PS ldif \t%s", mod1[0])
                        log.info("replacing manager in base with %s", ps_manager_dn)
                        try:
                            l_ps.modify_s(all_users[uid]['ps']['dn'], _mod1)
                        except Exception as e:
                            log.error('setting PS manager to %s failed', ps_manager_dn)
                            print e
    ##                        log.info('setting manager to DN %s', _ucm['dn'])
                        if mid:
                            _mod2 = [ ( ldap.MOD_REPLACE, Helper.ADUser.manager, _ucm['dn']) ]
                        else:
                            _mod2 = [ ( ldap.MOD_REPLACE, Helper.ADUser.manager, "") ]
                        if debug:
                            log.info("AD ldif \t%s", _mod2[0])
                        log.info("replacing manager for '%s' with %s", all_users[uid]['ad']['dn'], _ucm.get('dn'))
                        try:
                            l_svc.modify_s(all_users[uid]['ad']['dn'], _mod2)
                        except Exception as e:
                            log.error('setting AD manager to %s failed', _ucm.get('dn'))
                            print e
                        all_users[uid]['err'] = False
    #                        break
    finally:
        handle_ldap.data.user = _u_bak
        handle_ldap.data.passwd = _p_bak
        pass
## Main

@automain
def main():
    global log

    args = parse_args()
#    args = parse_args("-d -o all -u mohammad -p passwd -v".split())
    log = getLogger(args.root)

    if debug:
#        return
        pass
    if args.import_data:
        print '\n\timport starting at %s\n'%datetime.now()
        start = time()
        import_data(args)
        end = time()
        print '\n\timport ending at %s\nelapsed: %s\n\n'%(datetime.now(), end-start)

    if args.verify or args.apply:
        print '\n\tverification started at %s\n'%(datetime.now())
        start = time()
        verified_users = verify(args)
        print '\n\tverification ending at %s\nelapsed: %s\n\n'%(datetime.now(), time()-start)

    if args.apply:
        print '\n\tvupdate started at %s\n'%(datetime.now())
        start = time()
        apply(verified_users, args)
        end = time()
        print '\n\tverification ended at %s\nelapsed: %s\n'%(datetime.now(), end-start)
