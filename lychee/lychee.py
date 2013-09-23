#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, os, pwd
from datetime import datetime
import mimetypes
import logging
import argparse
from ConfigParser import SafeConfigParser

from network_listener import NetworkFileListener

CONFIG_FILE = '~/.lychee'

def init_sudo():
    if os.geteuid() == 0:
        # this is running as root
        main()
    else:
        print "You must be root to run this script."

        args = sys.argv
        if '--user' not in args:
            user = pwd.getpwuid(os.geteuid())
            args.extend(['--user', user.pw_name])

        import subprocess
        subprocess.call(['sudo'] + args)

def main():
    parser = argparse.ArgumentParser(description='Lychee')
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true',
                        default=False,
                        help='enable debug output'
                        )
    parser.add_argument('--interface',
                        dest='interface',
                        default=None,
                        help='Change the interface to listen to')
    parser.add_argument('--user',
                        dest='user',
                        required=True,
                        default='root',
                        help='the owner of saved files')
    options = parser.parse_args()

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    config = SafeConfigParser()
    config.read(os.path.expanduser(CONFIG_FILE))

    mime_types = config.get("Filters", "mime_types")
    if mime_types is not None:
        mime_types = mime_types.split(',')
        mime_types = [s.lower().strip() for s in mime_types]
        options.mime_types = mime_types

    options.output_dir = config.get('Output', 'directory')
    if options.output_dir is None:
        raise Exception('Output directory must be set')

    options.output_dir = os.path.expanduser(options.output_dir)

    if options.interface is None:
        if config.has_section('Network'):
            options.interface = config.get('Network', 'interface', 'en0')
        else:
            options.interface = 'en0'

    l = Lychee(options)
    l.start()

class Lychee(object):

    def __init__(self, options):
        self.user = pwd.getpwnam(options.user)

        logging.info('Running as %s.' % self.user.pw_name)

        self.out_dir = options.output_dir
        self.ensure_path_exists(self.user, self.out_dir)

        logging.info('Output Path: %s' % self.out_dir)

        if options.mime_types is not None:
            logging.info('Filtering mime_types: %s' % ', '.join(options.mime_types))

        self.nfl = NetworkFileListener(options.interface, options.mime_types)
        self.nfl.on_file_downlaoded = self._on_file_loaded

    def ensure_path_exists(self, owner, path):
        if os.path.exists(path):
            return

        logging.info('Creating Directory: %s' % path)

        os.setegid(owner.pw_gid)
        os.seteuid(owner.pw_uid)
        os.makedirs(path)
        os.setegid(0)
        os.seteuid(0)

    def start(self):
        self.nfl.start()

    def _on_file_loaded(self, f):

        ext = mimetypes.guess_extension(f.mime_type, True)

        if ext is None:
            logging.error('Could not determine mime_type')
            return

        filename = '%s%s' % (str(datetime.now()), ext)

        out_file = os.path.join(self.out_dir, filename)

        logging.info('Writing file %s' % out_file)

        with open(out_file, 'w') as fp:
            for b in f.bytes:
                fp.write(b)

            os.fchown(fp.fileno(), self.user.pw_uid, self.user.pw_gid)

        logging.info('Writing complete.')

if __name__ == '__main__':
    init_sudo()
