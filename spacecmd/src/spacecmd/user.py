#
# Licensed under the GNU General Public License Version 3
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright 2013 Aron Parsons <aronparsons@gmail.com>
# Copyright (c) 2013--2018 Red Hat, Inc.
#

# NOTE: the 'self' variable is an instance of SpacewalkShell

# wildcard import
# pylint: disable=W0401,W0614

# unused argument
# pylint: disable=W0613

# invalid function name
# pylint: disable=C0103

import gettext
import shlex
from getpass import getpass
try:
    from xmlrpc import client as xmlrpclib
except ImportError:
    import xmlrpclib
from spacecmd.i18n import _N
from spacecmd.utils import *

translation = gettext.translation('spacecmd', fallback=True)
try:
    _ = translation.ugettext
except AttributeError:
    _ = translation.gettext

def help_user_create(self):
    print(_('user_create: Create an user'))
    print(_('''usage: user_create [options])

options:
  -u USERNAME
  -f FIRST_NAME
  -l LAST_NAME
  -e EMAIL
  -p PASSWORD
  --pam enable PAM authentication'''))


def do_user_create(self, args):
    arg_parser = get_argument_parser()
    arg_parser.add_argument('-u', '--username')
    arg_parser.add_argument('-f', '--first-name')
    arg_parser.add_argument('-l', '--last-name')
    arg_parser.add_argument('-e', '--email')
    arg_parser.add_argument('-p', '--password')
    arg_parser.add_argument('--pam', action='store_true')

    (args, options) = parse_command_arguments(args, arg_parser)

    if is_interactive(options):
        options.username = prompt_user(_('Username:'), noblank=True)
        options.first_name = prompt_user(_('First Name:'), noblank=True)
        options.last_name = prompt_user(_('Last Name:'), noblank=True)
        options.email = prompt_user(_('Email:'), noblank=True)
        options.pam = self.user_confirm(_('PAM Authentication [y/N]:'),
                                        nospacer=True,
                                        integer=True,
                                        ignore_yes=True)

        options.password = ''
        while options.password == '':
            password1 = getpass(_('Password: '))
            password2 = getpass(_('Repeat Password: '))

            if password1 == password2:
                options.password = password1
            elif password1 == '':
                logging.warning(_N('Password must be at least 5 characters'))
            else:
                logging.warning(_N("Passwords don't match"))
    else:
        if not options.username:
            logging.error(_N('A username is required'))
            return 1

        if not options.first_name:
            logging.error(_N('A first name is required'))
            return 1

        if not options.last_name:
            logging.error(_N('A last name is required'))
            return 1

        if not options.email:
            logging.error(_N('An email address is required'))
            return 1

        if not options.password and not options.pam:
            logging.error(_N('A password is required'))
            return 1

        if options.pam:
            options.pam = 1
            # API requires a non-None password even though it's not used
            # when PAM is enabled
            if options.password:
                logging.warning(_N("Note: password was ignored due to PAM mode"))
            options.password = ""
        else:
            options.pam = 0

    self.client.user.create(self.session,
                            options.username,
                            options.password,
                            options.first_name,
                            options.last_name,
                            options.email,
                            options.pam)

    return 0

####################


def help_user_delete(self):
    print(_('user_delete: Delete an user'))
    print(_('usage: user_delete NAME'))


def complete_user_delete(self, text, line, beg, end):
    return tab_completer(self.do_user_list('', True), text)


def do_user_delete(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 1:
        self.help_user_delete()
        return 1

    name = args[0]

    if self.options.yes or self.user_confirm('Delete this user [y/N]:'):
        self.client.user.delete(self.session, name)
        return 0
    else:
        return 1

####################


def help_user_disable(self):
    print(_('user_disable: Disable an user account'))
    print(_('usage: user_disable NAME'))


def complete_user_disable(self, text, line, beg, end):
    return tab_completer(self.do_user_list('', True), text)


def do_user_disable(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 1:
        self.help_user_disable()
        return 1

    name = args[0]

    self.client.user.disable(self.session, name)

    return 0

####################


def help_user_enable(self):
    print(_('user_enable: Enable an user account'))
    print(_('usage: user_enable NAME'))


def complete_user_enable(self, text, line, beg, end):
    return tab_completer(self.do_user_list('', True), text)


def do_user_enable(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 1:
        self.help_user_enable()
        return 1

    name = args[0]

    self.client.user.enable(self.session, name)

    return 0

####################


def help_user_list(self):
    print(_('user_list: List all users'))
    print(_('usage: user_list'))


def do_user_list(self, args, doreturn=False):
    users = self.client.user.listUsers(self.session)
    users = sorted([u.get('login') for u in users])

    if doreturn:
        return users
    if users:
        print('\n'.join(users))

    return None

####################


def help_user_listavailableroles(self):
    print(_('user_listavailableroles: List all available roles for users'))
    print(_('usage: user_listavailableroles'))


def do_user_listavailableroles(self, args, doreturn=False):
    roles = self.client.user.listAssignableRoles(self.session)

    if doreturn:
        return roles
    if roles:
        print('\n'.join(sorted(roles)))
    else:
        logging.error(_N("No roles has been found"))

    return None

####################


def help_user_addrole(self):
    print(_('user_addrole: Add a role to an user account'))
    print(_('usage: user_addrole USER ROLE'))


def complete_user_addrole(self, text, line, beg, end):
    parts = line.split(' ')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)
    elif len(parts) == 3:
        return tab_completer(self.do_user_listavailableroles('', True),
                             text)

    return None


def do_user_addrole(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 2:
        self.help_user_addrole()
        return 1

    user = args[0]
    role = args[1]

    self.client.user.addRole(self.session, user, role)

    return 0

####################


def help_user_removerole(self):
    print(_('user_removerole: Remove a role from an user account'))
    print(_('usage: user_removerole USER ROLE'))


def complete_user_removerole(self, text, line, beg, end):
    parts = line.split(' ')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)
    elif len(parts) == 3:
        # only list the roles currently assigned to this user
        roles = self.client.user.listRoles(self.session, parts[1])
        return tab_completer(roles, text)

    return None


def do_user_removerole(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 2:
        self.help_user_removerole()
        return 1

    user = args[0]
    role = args[1]

    self.client.user.removeRole(self.session, user, role)

    return 0

####################


def help_user_details(self):
    print(_('user_details: Show the details of an user'))
    print(_('usage: user_details USER ...'))


def complete_user_details(self, text, line, beg, end):
    return tab_completer(self.do_user_list('', True), text)


def do_user_details(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if not args:
        self.help_user_details()
        return 1

    add_separator = False

    for user in args:
        try:
            details = self.client.user.getDetails(self.session, user)

            roles = self.client.user.listRoles(self.session, user)

            groups = \
                self.client.user.listAssignedSystemGroups(self.session,
                                                          user)

            default_groups = \
                self.client.user.listDefaultSystemGroups(self.session,
                                                         user)
        except xmlrpclib.Fault as exc:
            logging.warning(_N('%s is not a valid user') % user)
            logging.debug("Error '{}' while getting data about user '{}': {}".format(
                exc.faultCode, user, exc.faultString))
            continue

        org_name = self.client.org.getDetails(self.session, details.get('org_id')).get("name")

        if add_separator:
            print(self.SEPARATOR)
        add_separator = True

        print(_('Username:      %s') % user)
        print(_('First Name:    %s') % details.get('first_name'))
        print(_('Last Name:     %s') % details.get('last_name'))
        print(_('Email Address: %s') % details.get('email'))
        print(_('Organisation:  %s') % org_name)
        print(_('Last Login:    %s') % details.get('last_login_date'))
        print(_('Created:       %s') % details.get('created_date'))
        print(_('Enabled:       %s') % details.get('enabled'))

        if roles:
            print('')
            print(_('Roles'))
            print('-----')
            print('\n'.join(sorted(roles)))

        if groups:
            print('')
            print(_('Assigned Groups'))
            print('---------------')
            print('\n'.join(sorted([g.get('name') for g in groups])))

        if default_groups:
            print('')
            print(_('Default Groups'))
            print('--------------')
            print('\n'.join(sorted([g.get('name') for g in default_groups])))

    return 0

####################


def help_user_addgroup(self):
    print(_('user_addgroup: Add a group to an user account'))
    print(_('usage: user_addgroup USER <GROUP ...>'))


def complete_user_addgroup(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append('')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)
    elif len(parts) > 2:
        return tab_completer(self.do_group_list('', True), parts[-1])

    return None


def do_user_addgroup(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) < 2:
        self.help_user_addgroup()
        return 1

    user = args.pop(0)
    groups = args

    self.client.user.addAssignedSystemGroups(self.session,
                                             user,
                                             groups,
                                             False)

    return 0

####################


def help_user_adddefaultgroup(self):
    print(_('user_adddefaultgroup: Add a default group to an user account'))
    print(_('usage: user_adddefaultgroup USER <GROUP ...>'))


def complete_user_adddefaultgroup(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append('')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)
    elif len(parts) > 2:
        return tab_completer(self.do_group_list('', True), parts[-1])

    return None


def do_user_adddefaultgroup(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) < 2:
        self.help_user_adddefaultgroup()
        return 1

    user = args.pop(0)
    groups = args

    self.client.user.addDefaultSystemGroups(self.session,
                                            user,
                                            groups)

    return 0

####################


def help_user_removegroup(self):
    print(_('user_removegroup: Remove a group to an user account'))
    print(_('usage: user_removegroup USER <GROUP ...>'))


def complete_user_removegroup(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append('')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)
    elif len(parts) > 2:
        # only list the groups currently assigned to this user
        groups = self.client.user.listAssignedSystemGroups(self.session,
                                                           parts[1])
        return tab_completer([g.get('name') for g in groups], parts[-1])

    return None


def do_user_removegroup(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) < 2:
        self.help_user_removegroup()
        return 1

    user = args.pop(0)
    groups = args

    self.client.user.removeAssignedSystemGroups(self.session,
                                                user,
                                                groups,
                                                True)

    return 0

####################


def help_user_removedefaultgroup(self):
    print(_('user_removedefaultgroup: Remove a default group from an ' +
            'user account'))
    print(_('usage: user_removedefaultgroup USER <GROUP ...>'))


def complete_user_removedefaultgroup(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append('')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)
    elif len(parts) > 2:
        # only list the groups currently assigned to this user
        groups = self.client.user.listDefaultSystemGroups(self.session,
                                                          parts[1])
        return tab_completer([g.get('name') for g in groups], parts[-1])

    return None


def do_user_removedefaultgroup(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) < 2:
        self.help_user_removedefaultgroup()
        return 1

    user = args.pop(0)
    groups = args

    self.client.user.removeDefaultSystemGroups(self.session,
                                               user,
                                               groups)

    return 0

####################


def help_user_setfirstname(self):
    print(_('user_setfirstname: Set an user accounts first name field'))
    print(_('usage: user_setfirstname USER FIRST_NAME'))


def complete_user_setfirstname(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append(' ')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)

    return None


def do_user_setfirstname(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 2:
        self.help_user_setfirstname()
        return 1

    user = args.pop(0)
    details = {'first_name': args.pop(0)}

    self.client.user.setDetails(self.session, user, details)

    return 0

####################


def help_user_setlastname(self):
    print(_('user_setlastname: Set an user accounts last name field'))
    print(_('usage: user_setlastname USER LAST_NAME'))


def complete_user_setlastname(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append(' ')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)

    return None


def do_user_setlastname(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 2:
        self.help_user_setlastname()
        return 1

    user = args.pop(0)
    details = {'last_name': args.pop(0)}

    self.client.user.setDetails(self.session, user, details)

    return 0

####################


def help_user_setemail(self):
    print(_('user_setemail: Set an user accounts email field'))
    print(_('usage: user_setemail USER EMAIL'))


def complete_user_setemail(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append(' ')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)

    return None


def do_user_setemail(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 2:
        self.help_user_setemail()
        return 1

    user = args.pop(0)
    details = {'email': args.pop(0)}

    self.client.user.setDetails(self.session, user, details)

    return 0

####################


def help_user_setprefix(self):
    print(_('user_setprefix: Set an user accounts name prefix field'))
    print(_('usage: user_setprefix USER PREFIX'))


def complete_user_setprefix(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append(' ')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)

    return None


def do_user_setprefix(self, args):
    args, _ = parse_command_arguments(args, get_argument_parser())

    if not 0 < len(args) < 3:             # pylint: disable=len-as-condition
        self.help_user_setprefix()
        return 1

    user = args.pop(0)
    if not args:
        # clearing prefix with a space currently does not work
        # spacewalk requires a space to clear the prefix but the
        # space seems to be stripped when submitted to the API gateway
        # attempts to use %x20 and \u0020 (among others) also fail
        details = {'prefix': ' '}
    else:
        details = {'prefix': args.pop(0)}

    self.client.user.setDetails(self.session, user, details)

    return 0

####################


def help_user_setpassword(self):
    print(_('user_setpassword: Set an user accounts name prefix field'))
    print(_('usage: user_setpassword USER PASSWORD'))


def complete_user_setpassword(self, text, line, beg, end):
    parts = shlex.split(line)
    if line[-1] == ' ':
        parts.append(' ')

    if len(parts) == 2:
        return tab_completer(self.do_user_list('', True), text)

    return None


def do_user_setpassword(self, args):
    arg_parser = get_argument_parser()

    (args, _options) = parse_command_arguments(args, arg_parser)

    if len(args) != 2:
        self.help_user_setpassword()
        return 1

    user = args.pop(0)
    details = {'password': args.pop(0)}

    self.client.user.setDetails(self.session, user, details)

    return 0
