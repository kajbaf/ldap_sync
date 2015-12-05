__author__ = 'Mohammad Kajbaf'
__VERSION__ = '1.0.dev'

import sys
sys.path.append(
import ldap
from os import fdopen
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
from ldap_helper import init_ldap, init_ldaps, search_ldap, login_ps, login_active, data, add_ldap_object, data
from data_list import *

_root = kajlib.path(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../files'))
roles = (_root / 'roles.lst').open('r').read()

@automain
def main():
    with login_ps() as LDAP:
    #for LDAP in ['X']:
        for u in 'Staff', 'Vendor':
            #break
            for d in div:
                role = {'eTRoleName':'ADD Division %s \(%s\)'%(div[d], u),
                        'eTDescription': div[d],
                        'eTComments': 'div %s'%div[d],
                        'eTDepartment': u,
                        'eTCustomField01': 'AP',
                        'eTCustomField02': 'ADD',
                        'eTCustomField03': 'DIV',
                        'eTCustomField04': d,
    ##                    'eTIncludedRoleDN': 'eTRoleName=ADD Global,eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
                }
                try:
                    add_ldap_object(LDAP, data.roleFilter, role['eTRoleName'], data.roleNameTemplate, data.roleType, data.baseDNRole, role, DEBUG=True)
                except ldap.ALREADY_EXISTS as e:
                    print e
                    pass
                except Exception as e:
                    raise e
            del d
        del u
        VendorOrStaff = lambda n : ('Vendor' if n == 'V' else 'Staff')
        for n in inet:
            role = {'eTRoleName':'ADD Internet %s'  %inet[n][1],
                    'eTDescription': inet[n][0],
                    'eTComments': 'inet %s'% n,
                    'eTDepartment': VendorOrStaff(n),
                    'eTCustomField01': 'AP',
                    'eTCustomField02': 'ADD',
                    'eTCustomField03': 'INET',
                    'eTCustomField04': n,
            }
            try:
                add_ldap_object(LDAP, data.roleFilter, role['eTRoleName'], data.roleNameTemplate, data.roleType, data.baseDNRole, role, DEBUG=True)
            except ldap.ALREADY_EXISTS as e:
                print e
                pass
            except Exception as e:
                raise e
        del n
        for l in loc:
            #break
            role = {'eTRoleName':'ADD Office %s'%(loc[l],),
                    'eTDescription': loc[l],
                    'eTComments': 'loc %s'%loc[l],
                    'eTDepartment': 'ALL',
                    'eTCustomField01': 'AP',
                    'eTCustomField02': 'ADD',
                    'eTCustomField03': 'LOC',
                    'eTCustomField04': l,
    ##                    'eTIncludedRoleDN': 'eTRoleName=ADD Global,eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
            }
            try:
                add_ldap_object(LDAP, data.roleFilter, role['eTRoleName'], data.roleNameTemplate, data.roleType, data.baseDNRole, role, DEBUG=True)
            except ldap.ALREADY_EXISTS as e:
                print e
                pass
            except Exception as e:
                raise e
        del l


