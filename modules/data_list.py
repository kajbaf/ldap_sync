from os import fdopen
import time
from kajlib import automain, warning, error, getstr
import kajlib
import getpass
import unittest
import argparse
import csv
import tempfile
import sys
import ldap
import ldap.modlist as modlist

_root = kajlib.path(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../files'))
groups = (_root / 'ad_groups.lst').open('r').read()

AD_Groups = groups.read()

loc = {'TW1': '#T1', 'HMN': '#Hamedan', 'BBL': '#Babol', 'AWZ': '#Ahvaz Regional Office', 'TBZ': '#Tabriz', 'SHZ': '#Shiraz', 'MSD': '#Mashad', 'TE2': '#T2', 'THQ': '#HQ', 'ISN': '#Esfahan', 'YZD': '#Yazd'}
div = {'CEO': 'CEO Office', 'PROC': 'Procurement', 'MO': 'Monitoring Office', 'CPG': 'Capital Program Group', 'HR': 'Human Resources', 'BRM': 'Business Risk Management', 'MKT': 'Marketing', 'NWG': 'Network', 'L&R': 'Legal & Regulatory', 'CS': 'Corporate Services', 'CR': 'Customer Relations', 'S&D': 'Sales & Distribution', 'EB': 'Enterprise Business', 'FIN': 'Finance', 'ITS': 'Information Technology Services', 'COO': 'COO Office'}
div2 = dict(zip( div.values(), div.keys()))
inet = {'V': ('Vendors', 'Vendor'), 'T': ('Specialists', 'Temp user'), '1': ('Specialists', 'Level-1'), '2': ('Specialists', 'Level-2'), '2H': ('Specialists', 'Level-2H'), '3': ('Managers', 'Level-3'), '3H': ('Managers', 'Level-3H'), '4': ('Managers', 'Level-4'), '5': ('Executives', 'Level-5')}
csvfile = _root / 'Default Groups.csv'

import ImportRoles

class ObjectTemplate(object):
    nameTemplate = ''
    descriptionTemplate = 'eTDescription'
    objectClass = ''
    baseDN = '%s,eTNamespaceName=CommonObjects,dc=im,dc=eta'
    baseFilter = "(&(objectClass=" + objectClass + ")%s)"
    searchFilter = baseFilter % "(" + nameTemplate + "=%s)"
    defaultAttributes = {"objectClass": objectClass}
    attributes = {}
    dn = ''
    def __init__(self):
        assert type(self) is not ObjectTemplate
        assert isinstance(self, ObjectTemplate)
        
    def add_ldap_object(self, l, scope=ldap.SCOPE_SUBTREE, DEBUG=False):
        """adds a new object to a ldap server
        @rtype : string
        """
        objectname = self.attributes[self.nameTemplate]
        try:
            assert not '*' in objectname
        except:
            raise ldap.INVALID_DN_SYNTAX("wild-cards is not allowed in the object's name")
        base = self.baseDN
        try:
            assert not '%' in base
        except:
            raise ldap.INVALID_DN_SYNTAX("unresolved baseTemplate")

        obj_list = []
        try:
            obj_list = ImportRoles.search_ldap(l, self.searchFilter, objectname, base, attributes=[self.nameTemplate])
        except ldap.LDAPError as e:
            e2 = Exception('Connection Error')
            e2.args += (e,)
            raise e2
        except:
            pass
        finally:
            if obj_list and len(obj_list):
                raise ldap.ALREADY_EXISTS('%s object exists "%s"' % (self.objectClass, obj_list[0][self.nameTemplate]))
        try:
            assert self.dn
            assert self.attributes
            dn = self.dn
            ldif = modlist.addModlist(self.attributes)
            print ldif
            l.add_s(dn, ldif)
        except ldap.LDAPError as e:
            e2 = Exception('Connection Error')
            e2.args += (e,)
            raise e2

        try:
            obj_list = ImportRoles.search_ldap(l, self.searchFilter, objectname, base, attributes=[self.nameTemplate])
        except ldap.LDAPError as e:
            e2 = Exception('Connection Error')
            e2.args += (e,)
            raise e2
        else:
            flag = False
            if obj_list and len(obj_list):
                for o in obj_list:
                    if isinstance(o, dict) and 'dn' in o and o['dn'].lower()==self.dn.lower():
                        flag = True
                        break
            if flag is False:
                raise ldap.LDAPError('%s object not created %s' % (self.objectClass, objectname))
            return o

    def mod_ldap_object(self, l, scope=ldap.SCOPE_SUBTREE, DEBUG=False):
        """modifies an object on a ldap server
        @rtype : string
        """
        objectname = self.attributes[self.nameTemplate]
        try:
            assert not '*' in objectname
        except:
            raise ldap.INVALID_DN_SYNTAX("wild-cards is not allowed in the object's name")
        base = self.baseDN
        try:
            assert not '%' in base
        except:
            raise ldap.INVALID_DN_SYNTAX("unresolved baseTemplate")

        obj_list = []
        try:
            obj_list = ImportRoles.search_ldap(l, self.searchFilter, objectname, base, attributes=[self.nameTemplate])
        except ldap.LDAPError as e:
            e2 = Exception('Connection Error')
            e2.args += (e,)
            raise e2
        except:
            pass
        finally:
            if obj_list and len(obj_list):
                raise ldap.ALREADY_EXISTS('%s object exists "%s"' % (self.objectClass, obj_list[0][self.nameTemplate]))

        try:
            assert self.dn
            assert self.attributes
            dn = self.dn
            ldif = modlist.addModlist(self.attributes)
            print ldif
            l.add_s(dn, ldif)
        except ldap.LDAPError as e:
            e2 = Exception('Connection Error')
            e2.args += (e,)
            raise e2

        try:
            obj_list = ImportRoles.search_ldap(l, self.searchFilter, objectname, base, attributes=[self.nameTemplate])
        except ldap.LDAPError as e:
            e2 = Exception('Connection Error')
            e2.args += (e,)
            raise e2
        else:
            flag = False
            if obj_list and len(obj_list):
                for o in obj_list:
                    if isinstance(o, dict) and 'dn' in o and o['dn'].lower()==self.dn.lower():
                        flag = True
                        break
            if flag is False:
                raise ldap.LDAPError('%s object not created %s' % (self.objectClass, objectname))
            return o

class ADAccountTemplate(ObjectTemplate):
    nameTemplate = 'eTADSPolicyName'
    objectClass = 'eTADSPolicy'
    baseDN = ObjectTemplate.baseDN % 'eTADSPolicyContainerName=Active Directory Policies'
    baseFilter = '(&(objectClass=eTADSPolicy)%s)'
    searchFilter = baseFilter % '(eTADSPolicyName=%s)'
    defaultAttributes = {'objectClass':objectClass,'eTADSAccountName':r'%#eTCustomField01%','eTADSobjectClass':'user','eTADSsAMAccountName':r'%AC%',
                         'eTADSUniversalGroupOnly':'0','eTADSuserPrincipalName':r'%AC%','eTPropagateChanges':'0','eTStrongSync':'0','eTADSdisplayName':'%UN%'}
    customAttributes = ['eTADSmemberOf', 'eTPolicyName']
    attributes = {}
    dn = ''

    def __init__(self, Name, Description, ADGroups=[], otherAttributes={}):
##        super(ObjectTemplate, self).__init__(self)
        self.attributes = { i:self.defaultAttributes[i] for i in self.defaultAttributes }
        self.attributes[self.nameTemplate] = Name
        self.attributes['eTPolicyName'] = Name
        self.attributes[self.descriptionTemplate] = Description
        self.attributes['eTADSmemberOf'] = [ g.split('DC')[0] + 'DC=?' for g in ADGroups ]
        for attr in self.customAttributes:
            assert attr in self.attributes
        for attr in otherAttributes:
            assert not attr in self.attributes
            self.attributes[attr] = otherAttributes[attr]
        self.dn = '%s=%s,%s'%(self.nameTemplate, Name, self.baseDN)

class ProvisioningRole(ObjectTemplate):
    nameTemplate = 'eTRoleName'
    objectClass = 'eTRole'
    baseDN = ObjectTemplate.baseDN % 'eTRoleContainerName=Roles'
    baseFilter = '(&(objectClass=eTRole)%s)'
    searchFilter = baseFilter % '(eTRoleName=%s)'
    defaultAttributes = {'objectClass':objectClass,'eTCustomField01':'AP','eTCustomField02':'ADD'}
    customAttributes = ['eTCustomField03', 'eTCustomField04', 'eTComments', 'eTDepartment']
    attributes = {}
    dn = ''

    def __init__(self, Name, Description, Comment, Type, Code, Scope, otherAttributes={}):
##        super(ObjectTemplate, self).__init__(self)
        self.attributes = { i:self.defaultAttributes[i] for i in self.defaultAttributes }
        self.attributes[self.nameTemplate] = Name
        self.attributes[self.descriptionTemplate] = Description
        self.attributes['eTComments'] = Comment
        self.attributes['eTCustomField03'] = Type
        self.attributes['eTCustomField04'] = Code
        self.attributes['eTDepartment'] = Scope
        for attr in self.customAttributes:
            assert attr in self.attributes
        for attr in otherAttributes:
            assert not attr in self.attributes
            self.attributes[attr] = otherAttributes[attr]
        self.dn = '%s=%s,%s'%(self.nameTemplate, Name, self.baseDN)


@automain
def main():
    RoleList = []
    with csvfile.open() as f:
        groups_csv = csv.DictReader(f)
        for g in groups_csv:
            g['Groups'] = []
            for i in [1, 2, 3, 4]:
                _gn = 'name%s'%i 
                if _gn in g and g[_gn]:
                    g['Groups'].append(g[_gn])
                    if g['type'] == 'loc':
                        g['code'] = g['Name']
                        g['Name'] = loc[g['code']]
                    elif g['type'] == 'div':
                        g['code'] = div2[g['Name']]
                    else:
                         raise Exception('Wrong Code')
            RoleList.append(g)
            
    #with ImportRoles.login_ps() as LDAP:
    for LDAP in ['X']:
        ATName = r'ptADAccount %s_%s_%s'
        ATDesc = r'AD %s %s (%s) ActiveDirectory Account Template'
        ATGroups = []
        for role in RoleList:
            if role['Type'] == 'loc':
                Name = ATName % ('loc',role['Code'],role['Scope'])
                Desc = ATDesc % ('Office', role['name1'], role['Scope'])
                Groups = [ AD_Groups[_g] for _g in role['Groups'] ]
            elif role['Type'] == 'div':
                Name = ATName % ('div',role['Code'],role['Scope'])
                Desc = ATDesc % ('Division', role['Name'], role['Scope'])
                Groups = [ AD_Groups[_g] for _g in role['Groups'] ]
            elif role['Type'] == 'int':
                Name = ATName % ('int',role['Code'],role['Scope'])
                Desc = ATDesc % ('Internet', role['Name'], role['Scope'])
                Groups = [ AD_Groups[_g] for _g in role['Groups'] ]
            else:
                continue
            ptAT = ADAccountTemplate(Name, Desc, Groups)
            try:
                at = ptAT.add_ldap_object(LDAP)
            except ldap.ALREADY_EXISTS as e:
                print e
                continue
            except:
                return
            print at

#        continue
        RLName1 = r'AD %s %s'
        RLName2 = r'AD %s %s (%s)'
        RLComm = r'%s %s'
        RLDesc = r'%s'
        RLType = ''
        RLScope = ''
        RLCode = ''
        for role in RoleList:
            if role['Type'] == 'loc':
                Name = RLName1 % ('Office',loc['Name'])
                Desc = ATDesc % ('Office', role['name1'], role['Scope'])
                Groups = [ AD_Groups[_g] for _g in role['Groups'] ]
            elif role['Type'] == 'div':
                Name = ATName % ('div',role['Code'],role['Scope'])
                Desc = ATDesc % ('Division', role['Name'], role['Scope'])
                Groups = [ AD_Groups[_g] for _g in role['Groups'] ]
            else:
                continue
            ptAT = ADAccountTemplate(Name, Desc, Groups)
            try:
                at = ptAT.add_ldap_object(LDAP)
            except ldap.ALREADY_EXISTS as e:
                print e
                continue
            except:
                return
            print at
            continue
            for d in div:
                role = {'eTRoleName':'AD Division %s (%s)'%(div[d], u),
                        'eTDescription': div[d],
                        'eTComments': 'div %s'%div[d],
                        'eTDepartment': u,
                        'eTCustomField01': 'AP',
                        'eTCustomField02': 'AD',
                        'eTCustomField03': 'DIV',
                        'eTCustomField04': d,
    ##                    'eTIncludedRoleDN': 'eTRoleName=AD Global,eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
                }
                try:
                    add_ldap_object(LDAP, data.roleFilter, role['eTRoleName'], data.roleNameTemplate, data.roleType, data.baseDNRole, role, DEBUG=True)
                except ldap.ALREADY_EXISTS as e:
                    print e
                    pass
                except Exception as e:
                    raise e
            del d
            continue
            for n in inet:
                role = {'eTRoleName':'AD Internet %s (%s)'%(n, u),
                        'eTDescription': n,
                        'eTComments': 'inet %s'%n,
                        'eTDepartment': u,
                        'eTCustomField01': 'AP',
                        'eTCustomField02': 'AD',
                        'eTCustomField03': 'INET',
                        'eTCustomField04': n,
    ##                    'eTIncludedRoleDN': 'eTRoleName=AD Global,eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
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
            break
            role = {'eTRoleName':'AD Office %s'%(loc[l],),
                    'eTDescription': loc[l],
                    'eTComments': 'loc %s'%loc[l],
                    'eTDepartment': 'ALL',
                    'eTCustomField01': 'AP',
                    'eTCustomField02': 'AD',
                    'eTCustomField03': 'LOC',
                    'eTCustomField04': l,
    ##                    'eTIncludedRoleDN': 'eTRoleName=AD Global,eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
            }
            try:
                add_ldap_object(LDAP, ImportRoles.data.roleFilter, role['eTRoleName'], ImportRoles.data.roleNameTemplate, ImportRoles.data.roleType, ImportRoles.data.baseDNRole, role, DEBUG=True)
            except ldap.ALREADY_EXISTS as e:
                print e
                pass
            except Exception as e:
                raise e
        del l
