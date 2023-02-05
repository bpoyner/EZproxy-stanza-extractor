#!/usr/bin/env python3

"""
    stanza.py
    
    (C) 2023 Brandon Poyner
    Released under MIT License 

    Extracts database stanzas from the EZproxy website to save as local files

    works with python3
    requires bs4 (BeautifulSoup4), requests, and html5lib
"""

from __future__ import print_function
import optparse, io, re, time
import shutil, subprocess, sys, os
if os.name == 'posix':
    import pwd, grp
import bs4, requests, html5lib

# default settings
stanza_file_permissions = {
    # File permissions for UNIX-like systems
    'posix': { 'file_owner': '',
               'file_group': '',
               'file_mode': 644 } 
}
general_settings = { 'debug': False,
                     'fetch_delay_seconds': 2,
                     'fetch_retry_count': 3}
if os.name == 'posix':
    general_settings['stanza_directory'] = '/usr/local/ezproxy/databases'
    general_settings['directory_sep'] = '/'
elif os.name == 'nt':
    general_settings['stanza_directory'] = 'c:\\temp'
    general_settings['directory_sep'] = '\\'

class Stanzas:
    _registry = []

    def __init__(self, url):
        self._registry.append(self)
        self.url=url
        self.success=0

class File_permissions:
    def __init__(self, perms):
        if os.name == 'posix':
            self.uid(perms['posix']['file_owner'])
            self.gid(perms['posix']['file_group'])
            self.omode(perms['posix']['file_mode'])

    if os.name == 'posix':
        # Permissions for Unix-like systems
        def uid(self,owner):
            if not owner:
                return -1
            try:
                # Get UID from username
                uid = pwd.getpwnam(owner).pw_uid
            except:
                uid = -2
            self.uid = uid
        def gid(self,group):
            if not group:
                return -1
            try:
                # Get GID from groupname
                gid = grp.getgrnam(group).gr_gid
            except:
                gid = -2
            self.gid = gid
        def omode(self,mode):
            if not mode:
                return -1
            elif isinstance(mode, str):
                # Mode is a string, convert to octal
                try:
                    mode=int(mode,base=8)
                except:
                    mode = -1
            elif isinstance(mode, int):
                # Mode is an integer, convert to octal
                mode=int(str(mode),base=8)
            else:
                # Mode is something else we can't handle
                mode = -1
            self.omode = mode

def debug(message):
    # Display debug messages if requested
    if general_settings['debug'] == True:
        # Write debug message to stderr
        sys.stderr.write("DEBUG: {0}{1}".format(message,os.linesep))

def stanza_check(stanza):
    """
        Verify the downloaded stanza meets the minimum requirements for a valid stanza
        All stanzas must contain both a title and url 
    """
    title_found = url_found = 0
    for line in io.StringIO(stanza):
        title_match=re.search('^title\s+(.*)', line, re.IGNORECASE)
        if title_match != None:
            if '-hide' in title_match.group(1).lower():
                # Not the primary title for this stanza
                continue
            title_found=1
        if re.search('^url\s+', line, re.IGNORECASE):
            url_found=1
        if title_found == 1 and url_found == 1:
            return 0
    return 1

def check_permissions(permissions):
    if os.name == 'posix':
        if permissions.uid == -2:
            sys.stderr.write("Error: No such owner {0}{1}".format(permissions.owner,os.linesep))
            sys.exit(1)
        if permissions.gid == -2:
            sys.stderr.write("Error: No such group {0}{1}".format(permissions.group,os.linesep))
            sys.exit(1)
        if permissions.omode == -1:
            sys.stderr.write("Error: Could not parse file mode {0}{1}".format(permissions.mode,os.linesep))
            sys.exit(1)

def set_stanza_permissions(file,permissions):
    if os.name == 'posix':
        # Only attempt to set file permissions on Unix-like systems
        error=0
        try:
            if permissions.omode >= 0:
                os.chmod(file,permissions.omode)
            else:
                raise Exception("Invalid permission")
        except:
            sys.stderr.write("Warning: Could not change file permissions to {0}{1}".format(str(permissions.omode),os.linesep))
            error+=1
        try:
            os.chown(file,permissions.uid,permissions.gid)
        except:
            sys.stderr.write("Warning: Could not set {0} ownership of {1}:{2} ({3}:{4}){5}".format(file,permissions.owner,permissions.group,str(permissions.uid),str(permissions.gid),os.linesep))
            error+=1
        if error > 0:
            return 1
        return 0

def includefile_name(includefile,url):
    # Use the filename if provided in web page, otherwise use the last part of the URL for the filename
    include_match=re.search('^includefile\s+(.*)', includefile, re.IGNORECASE)
    if include_match != None:
        include=includefile.replace('\n','')
        include=include.rsplit('/', 1)[-1]
    elif url:
        include=url.rsplit('/', 1)[-1].lower() + ".txt"
    include_match=re.search('^.*\.txt$', include, re.IGNORECASE)
    if include_match != None:
        return include
    else:
        sys.stderr.write("Warning: Could not determine stanza file name for {0}".format(url))
        return "stanza.txt"

def fetch_stanzas(urls):
    total_url_count=len(urls)-1
    current_url_count=0
    for url in urls:
        stanza = Stanzas(url)
        # Make request for web page - retry if failure detected
        for retry in range(general_settings['fetch_retry_count']):
            debug("request {0} for {1}".format(retry,url))
            try:
                req = requests.get(url)
            except requests.exceptions.RequestException as e:
                stanza.err_msg="Error: Could not retrieve url '{0}'".format(url)
                continue
            if (not req.ok):
                stanza.err_msg="Error: Request for URL {0} not successful".format(url)
                time.sleep(general_settings['fetch_delay_seconds'])
                continue
            stanza.success=1
            break
        if stanza.success == 0:
            debug("request for {0} failed".format(url))
            continue
        # Parse HTML with BeautifulSoup, find <pre> text
        debug("get request for {0} successful".format(url))
        html = bs4.BeautifulSoup(req.content, "html5lib")
        if (not html.find("pre")):
            stanza.err_msg="Error: Could not find <pre> element in {0}".format(url)
            stanza.success=0
            continue
        tags = html.find_all("pre")
        stanza_text=tags[0].text
        if len(tags) > 1:
            includefile=includefile_name(tags[1].text,url)
        else:
            includefile=includefile_name('',url)
        if stanza_check(stanza_text) == 1:
            stanza.err_msg="Error: Stanza for {0} not appear to be valid format".format(url)
            stanza.success=0
            continue
        stanza.success=1
        stanza.stanza=stanza_text
        stanza.outfile=includefile
        if current_url_count < total_url_count:
            # as this is a web crawl, pause between requests
            debug("Delaying {0} seconds between requests".format(general_settings['fetch_delay_seconds']))
            time.sleep(general_settings['fetch_delay_seconds'])
            current_url_count += 1

def write_outfile(outfile,stanza,permissions):
    # Send to output file
    if os.path.exists(outfile) and os.path.isdir(outfile):
        sys.stderr.write("Error: Output file {0} cannot be a directory{1}".format(outfile,os.linesep))
        return 1
    elif os.path.exists(outfile) and os.path.isfile(outfile):
        # Output file already exists, make a backup file
        backupfile=outfile+".bak"
        sys.stderr.write("Backing up {0} as {1}{2}".format(outfile, backupfile, os.linesep))
        try:
            shutil.copy2(outfile,backupfile)
        except:
            sys.stderr.write("Could not create backup of {0} as {1}{2}".format(outfile, backupfile, os.linesep))
        set_stanza_permissions(backupfile,permissions)
    sys.stderr.write("Writing stanza as {0}{1}".format(outfile, os.linesep))
    try:
        # Output new stanza file
        file_out = open(outfile, "w")
        file_out.write(stanza)
        file_out.close()
    except:
        sys.stderr.write("Error: Could not write to {0}{1}".format(outfile, os.linesep));
        return 1
    set_stanza_permissions(outfile,permissions)
    return 0

def output_stanzas(outfile,permissions):
    multi_stanza=""
    for stanza in Stanzas._registry:
        if stanza.success == 1:
            if (general_settings['stanza_directory']) and not outfile:
                # Output each stanza as a separate file to a directory
                stanza_outfile=general_settings['stanza_directory'] + general_settings['directory_sep'] + stanza.outfile
                debug("writing output file for {0} to {1}".format(stanza.url,stanza_outfile))
                write_outfile(stanza_outfile,stanza.stanza,permissions)
            else:
                multi_stanza += stanza.stanza + os.linesep
    if (multi_stanza):
        # Remove extra line separator
        multi_stanza = multi_stanza[:multi_stanza.rfind(os.linesep)]
        if (outfile):
            # send all stanzas to one file
            write_outfile(outfile,multi_stanza)
        else:
            # send all stanzas to stdout
            print(multi_stanza, end='')

def display_errors():
    errors=0
    for stanza in Stanzas._registry:
        if stanza.success == 0:
            errors += 1
            print(stanza.err_msg)
    return(errors)

def main(argv):
    parser = optparse.OptionParser(usage='usage: %prog [options] [url [url]]',description="Extracts database stanzas from the OCLC EZproxy website to save as local files")
    parser.add_option("-f", "--outfile", dest='outputfile', metavar='[output file]', type='string', action='store', help="output stanzas in singular file")
    parser.add_option("-d", "--outdir", dest='outputdir', metavar='[output directory]', type='string', action='store', help="output stanza directory")
    parser.add_option("-u", "--url", dest='url', metavar='<url>', type='string', action='append', help="URL of stanza to extract")
    parser.add_option("--delay", dest='delay', metavar='[seconds]', type='int', action='store', help="Delay between fetch requests")
    parser.add_option("--retry", dest='retry', metavar='[attempts]', type='int', action='store', help="Number of fetch retry attempts")
    parser.add_option("--debug", dest='debug', action='store_true', help="display debug information")
    group = optparse.OptionGroup(parser, "Posix options", "Options for Unix-like systems")
    group.add_option("-o", "--owner", dest='f_owner', metavar='[file owner]', type='string', action='store', help="owner of output files")
    group.add_option("-g", "--group", dest='f_group', metavar='[file group]', type='string', action='store', help="group of output files")
    group.add_option("-p", "--permission", dest='f_permission', metavar='[file permission]', action='store', type='string', help="3 digit file permission mode for output files")
    parser.add_option_group(group)
    group = optparse.OptionGroup(parser, "Example", "{0} <url> <url> <url> --outdir /usr/local/ezproxy/databases".format(os.path.basename(__file__)))
    parser.add_option_group(group)
    (options, args) = parser.parse_args()
    urls = options.url
    outfile = options.outputfile
    if (os.name != 'posix' and (options.f_owner or options.f_group or options.f_permission)):
        sys.stderr.write("Error: File ownership and permissions are only supported with Unix-like systems{1}",format(os.linesep)) 
        raise SystemExit()

    # Override default settings
    if (options.f_owner):
        stanza_file_permissions['posix']['file_owner']=options.f_owner
    if (options.f_group):
        stanza_file_permissions['posix']['file_group']=options.f_group
    if (options.f_permission):
        stanza_file_permissions['posix']['file_mode']=options.f_permission
    if (options.outputdir):
        general_settings['stanza_directory']=options.outputdir
    if (options.delay):
        general_settings['fetch_delay_seconds']=options.delay
    if (options.retry):
        general_settings['fetch_retry_count']=options.delay
    if (options.debug):
        general_settings['debug']=options.debug

    # URL can also be specified without an option
    if args and urls:
        urls = urls + args
    elif args and not urls:
        urls = args
    if not urls:
        parser.print_help()
        sys.exit(1)

    permissions=File_permissions(stanza_file_permissions)
    check_permissions(permissions)
    fetch_stanzas(urls)
    output_stanzas(outfile,permissions)
    errors=display_errors()
    if errors > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main(sys.argv[1:])
