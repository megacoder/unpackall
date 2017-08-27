#!/usr/bin/python
# vim: filetype=python noet sw=4 ts=4

import	hashlib
import	os
import	re
import	stat
import	subprocess
import	sys
import	traceback
import	resource
import	fnmatch
from	contextlib		import	contextmanager

# http://stackoverflow.com/questions/189645/how-to-break-out-of-multiple-loops-in-python

@contextmanager
def	nested_break():
	class	NestedBreakException( Exception ):
		pass
	try:
		yield NestedBreakException
	except	NestedBreakException:
		pass

# Back to original code

class	InodeCheck( object ):

	def	__init__( self ):
		self.inodes = dict()

	def	consider( self, path ):
		keep = False
		try:
			st = os.stat( path )
			inode = ( st.st_dev, st.st_ino )
			if inode not in self.inodes:
				self.inodes[ inode ] = 0
				keep = True
		except Exception, e:
			pass
		return keep

	def	fconsider( self, f ):
		keep = False
		try:
			st = os.fstat( f )
			inode = ( st.st_dev, st.st_ino )
			if inode not in self.inodes:
				self.inodes[ inode ] = True
				keep = True
		except Exception, e:
			pass
		return keep

class	Walker( object ):

	def	__init__( self, callback = None, regex = None ):
		self.callback = callback
		self.regex     = regex
		return

	def	walk( self, origin ):
		inode_check = InodeCheck()
		for root, dirs, files in os.walk( origin ):
			# Purge directories we've visited before
			for dir in dirs:
				path = os.path.join( root, dir )
				if not inode_check.consider( path ):
					dirs.remove( dir )
			# Apply glob filtering to the filenames, directory
			# name are not checked.
			if self.regex:
				files = [
					# Glob the filenames, return only passes
					name for name in files if self.regex.search( name )
				]
			# Offer this up to caller
			yield root, dirs, files
		return

class	AttrDict( dict ):

	def	__init__( self, *args, **kwargs ):
		super( AttrDict, self ).__init__( *args, **kwargs )
		self.__dict__ = self
		return

	def	has_name( self, name ):
		return name in self.__dict__

class	UnpackAll( object ):

	VARIANTS = dict(
		default = AttrDict(
			prefix  = 'DUNNO',
			glob    = re.compile( r'^.*$' ),
			explode = True,
			md5     = True,
			info    = 'anonymous tarball'
		),
		unosw = AttrDict(
			prefix  = 'UNOSW',
			glob    = re.compile( r'^osw.*tar.*$' ),
			explode = True,
			md5     = True,
			info    = 'OSWatcher tarball'
		),
		unarchive = AttrDict(
			prefix	= 'ARCHIVE',
			glob    = re.compile( r'^.*tar.*$' ),
			explode = True,
			md5		= True,
			info	= 'OSWatcher archives'
		),
		unsos = AttrDict(
			prefix  = 'SOS',
			glob    = re.compile( r'^sosreport.*tar.*$' ),
			explode = True,
			md5		= True,
			info	= 'SOSREPORT archives'
		),
		unvmpinfo = AttrDict(
			prefix  = 'VMPINFO',
			glob    = re.compile( r'^.*vmpinfo.*tar.*$' ),
			explode = True,
			md5		= True,
			info	= 'VMPINFO3 archive'
		),
		untar = AttrDict(
			prefix  = 'UNTAR',
			glob    = re.compile( r'^.*tar.*$' ),
			explode = True,
			md5		= True,
			info	= 'generic tar(1) archive'
		),
	)

	def	__init__(
		self,
		variant = 'untar',
		verbose = False,
		perms = False,
		dry_run = False
	):
		self.variants = UnpackAll.VARIANTS.keys()
		self.perms    = perms
		self.set_verbose( verbose )
		self.set_dry_run( dry_run )
		self.set_variant( variant )
		self.variants.sort()
		return

	def	err_append( self, err, more ):
		if not err and not more:
			return None
		if err and not more:
			fmt = '{0}'
		elif not err and more:
			fmt = '{1}'
		else:
			fmt = '{0}\n{1}'
		return fmt.format( err, more )

	def	process( self, name, cleanup = True ):
		errors = []
		with nested_break() as TopLevel:
			if os.path.isdir( name ):
				# Recurse into directories.  Filesystem loops are avoided
				walker = Walker( regex = self.variant.glob )
				for root, dirs, files in walker.walk( name ):
					for file in files:
						path     = os.path.join( root, file )
						problems = self.process( path )
						if problems:
							errors += problems
							raise TopLevel
				raise TopLevel
			# Only ordinary files beyond this point
			if not os.path.isfile( name ):
				raise TopLevel
			if name.endswith( '.md5' ):
				# Check file associated with this MD5SUM check file
				# if there is any interest in that sort of thing.
				if self.variant.md5:
					problems = self._do_md5sum( name )
					if problems:
						errors += problems
			elif name.endswith( '.zip' ):
				if self.variant.explode:
					where = name[:-4]
					cmd = [
						'/bin/unzip',
						'-d',
						where,
						name
					]
					results = self._run( cmd )
					if results.errno:
						errors += results.stderr
					elif cleanup:
						cmd = [
							'/bin/rm',
							'-f',
							name
						]
						results = self._run( cmd, show = False )
						if results.errno:
							errors += results.stderr
			elif name.endswith( '.tgz' ):
				where = name[:-4]
				problems = self._explode_tarball( name, where )
				if problems:
					errors += problems
				elif cleanup:
					cmd = [
						'/bin/rm',
						'-f',
						name
					]
					results = self._run( cmd )
					if results.errno:
						errors += results.stderr
			elif name.endswith( '.7z' ):
				problems = [
					'cannot do 7z archives yet'
				]
				errors += problems
			elif name.find( '.tar' ) > -1:
				e = name.find( '.tar' )
				where = name[:e]
				problems = self._explode_tarball( name, where )
				if problems:
					errors += problems
			else:
				# Ignore this file.
				pass
		return errors if len(errors) else None

	def	print_lines( self, items, is_err = False ):
		if items:
			if is_err:
				fmt = '*** {0}'
			else:
				fmt = '    {0}'
			if not isinstance( items, list ):
				items = [ str(items) ]
			for item in items:
				for line in item.splitlines():
					print fmt.format( line )
		return

	def	get_variants( self ):
		if not self.verbose:
			# Give simple list of variant names
			for variant in self.variants:
				yield variant
			return
		# In verbose mode, return name, prefix, and short description
		key_width = max(
			map(
				len,
				self.variants
			)
		) + 1
		prefix_width = max(
			map(
				len,
				[ UnpackAll.VARIANTS[key].prefix for key in self.variants ]
			)
		)
		fmt = '{{0:>{0}}}  {{1:<{1}}}  {{2}}'.format(
			key_width,
			prefix_width
		)
		for key in self.variants:
			v = UnpackAll.VARIANTS[key]
			yield fmt.format(
				key,
				v.prefix,
				v.info,
			)
		return

	def	set_variant( self, arg0 = 'default' ):
		prog, _ = os.path.splitext(
			os.path.basename( arg0 )
		)
		if prog not in self.variants:
			raise ValueError( 'unknown variant name {0}'.format( prog ) )
		self.variant = UnpackAll.VARIANTS[prog]
		return

	def	set_dry_run( self, want = True ):
		self.dry_run = want
		return

	def	get_dry_run( self ):
		return self.dry_run

	def	set_md5_check( self, want = True ):
		self.variant.md5 = want
		return

	def	get_md5_check( self ):
		return self.variant.md5

	def	set_verbose( self, level = None ):
		if isinstance( level, bool ):
			self.verbose = 1 if level else 0
		elif isinstance( level, int ):
			try:
				self.verbose += level
			except:
				self.verbose = level
		else:
			raise ValueError(
				'unknown verbose value "{0}"'.format( level )
			)
		return

	def	get_verbose( self ):
		return self.verbose

	def	is_verbose( self, needed = 1 ):
		return True if self.verbose >= needed else False

	def	_chatter( self, s ):
		if self.is_verbose():
			print s
		return

	def	_collapse_lines( self, long_string ):
		result = []
		for line in long_string.splitlines():
			line = line.rstrip()
			if len(line):
				result.append( line )
		if len(result):
			result = '\n'.join( result )
		else:
			result = None
		return result

	def	_run( self, cmd, show = True ):
		if show or self.is_verbose():
			cli = ' '.join( cmd )
			self._chatter( '  {0}'.format( cli ) )
		# If doing a dry run, just print out what would be done
		# by prefixing the command with '/bin/echo'
		if self.dry_run:
			cmd = [ '/bin/echo' ] + cmd
		#
		results = AttrDict({
			'errno'  : -1,
			'stdout' : None,
			'stderr' : None,
		})
		try:
			po = subprocess.Popen(
				cmd,
				bufsize = 4 * resource.getpagesize(),
				stdout = subprocess.PIPE,
				stderr = subprocess.PIPE,
			)
			output, err    = po.communicate()
			results.errno  = po.returncode
			if len(output):
				results.stdout = output.splitlines()
			if len(err):
				results.stderr = err.splitlines()
		except Exception, e:
			why = [ '$ {0}'.format( ' '.join( cmd ) ) ] + traceback.format_exc().splitlines()
			if results.stderr:
				results.stderr += why
			else:
				results.stderr = why
		if show:
			if results.stdout:
				self.print_lines( results.stdout )
			if results.errno:
				self.print_lines(
					'{0}; errno={1}'.format(
						os.strerror( results.errno ),
						errno,
					),
					is_err = True
				)
			if results.stderr:
				self.print_lines( results.stderr, is_err = True )
		return results

	def	_do_untar( self, tn, where ):
		wrong = True
		# Try all known uncompress options.  The "auto" (a) option should
		# work in most cases but can fail if the tarball name has been
		# mangled.  As a last resort, maybe it's a plain tarball.
		for method in [ 'a', 'z', 'j', 'J', '' ]:
			cmd = [
				'/bin/tar',
				'-C',
				where,
				'--exclude=dev/*',	# Try avoiding device special nodes
				'--sparse',			# Handle sparse files like /v/l/lastlog
				'-m',
				'-x{0}{1}f'.format(
					method,
					'v' if self.verbose else '',
				),
				tn
			]
			results = self._run( cmd, show = False )
			if self.verbose:
				self.print_lines( results.stdout )
			if results.errno == 0:
				wrong = False
				break
		return wrong

	def	_do_md5sum( self, name ):
		if not name.endswith( '.md5' ):
			raise ValueError(
				'file {0} does not end with ".md5" as expected'.format(
					name
				)
			)
		errors = []
		with nested_break() as TopLevel:
			# Drop the extention to derive the subject file name
			subject, _ = os.path.splitext( name )
			self._chatter(
				'Checking {0} against {1}'.format( subject, name )
			)
			# Calculate MD5sum of the subject file
			chunksize = 3 * resource.getpagesize()
			try:
				hash = hashlib.md5()
				with open( subject, 'rb' ) as f:
					for chunk in iter( f.read, chunksize ):
						hash.update( chunk )
				calc_hash = hash.hexdigest()
			except Exception, e:
				errors += [
					'cannot compute md5sum for "{0}"'.format(
						subjext
					)
				]
				errors += traceback.format_exc().splitlines()
				raise TopLevel
			# Read the first (and only) digest string from MD5SUM file.
			# It should be a single file with one or two fields.  The
			# md5 digest is the first field either way.
			try:
				with open( name ) as f:
					tokens = f.readline().split()
			except Exception, e:
				errors += [
					'cannot get md5sum from "{0}"'.format(
						name
					)
				]
				errors += traceback.format_exc().splitlines()
				raise TopLevel
			# If md5 file is correctly formed, compare the md5 sums
			if len(tokens):
				digest = tokens[ 0 ]
				self._chatter(
					'File {0}: calc[{1}], real[{2}]'.format(
						name,
						calc_hash,
						digest
					)
				)
				if calc_hash.lower() != digest.lower():
					errors += [
						'  *** {0}'.format(
							'MD5 checksum differs: "{0}"'.format(
								subject
							)
						)
					]
					raise TopLevel
		return errors if len(errors) else None

	def	_do_chmod( self, where ):
		errors = []
		walker = Walker()
		for rootdir,dirs,files in walker.walk( where ):
			# Change directory permissions first
			perm = (
				stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC |
				stat.S_IRGRP | stat.S_IWGRP  | stat.S_IXGRP |
				stat.S_IROTH | stat.S_IWOTH  | stat.S_IXOTH |
				0
			)
			for name in sorted( dirs ):
				pn = os.path.join( rootdir, name )
				self._chatter(
					'Setting new dir permissions {0}: {1:04o}'.format(
						pn,
						perm
					)
				)
				cmd = [
					'/bin/chmod',
					'0777',
					pn
				]
				results = self._run( cmd )
				if results.errno:
					errors += results.stderr
			# Change files last
			for name in sorted( files ):
				path = os.path.join( rootdir, name )
				cmd = [
					'/bin/chmod',
					'0660',
					path
				]
				results = self._run( cmd )
				if results.errno:
					errors += results.stderr
		return errors if len(errors) else None

	def	_explode_dat( self, where ):
		suffixes = dict({
			'.dat.bz2' : [
				'/bin/bzip2',
				'--decompress',
				'--force',
				'--keep',
				'--quiet',
				'--',
			],
			'.dat.gz' : [
				'/bin/gzip',
				'--decompress',
				'--force',
#				'--keep',		# Doesn't have this, but should
				'--quiet',
				'--',
			],
			'.dat.xz' : [
				'/bin/xz',
				'--decompress',
				'--force',
				'--keep',
				'--quiet',
				'--',
			],
		})
		errors = []
		walker = Walker(
			re.compile( r'^osw.*$' )
		)
		for root, dirs, files in walker.walk( where ):
			self._chatter(
				'Scanning {0} for compressed OSWatcher files.'.format(
					where
				)
			)
			for file in files:
				cmd = None
				name, ext = os.path.splitext( file )
				if ext in suffixes:
					cmd = suffixes[ext] + [
						os.path.join( where, file )
					]
					results = self._run( cmd )
					if results.errno:
						errors += results.stderr
		if len(errors):
			self.print_lines( errors, is_err = True )
		return errors if len(errors) else None

	def	chmod( self, where ):
		""" This is a courtesy only.  No huhu if no worky. """
		walker = Walker()
		for root, dirs, files in walker.walk( where ):
			#
			for dir in dirs:
				cmd = [
					'/bin/chmod',
					'0777',
					dir
				]
				results = self._run( cmd )
			#
			for file in files:
				cmd = [
					'/bin/chmod',
					'0777',
					file
				]
				results = self._run( cmd )
		return

	def	_explode_tarball( self, tarball, where = None ):
		""" Explode tarball and expand the resulting directory tree
			for other tarballs to expand.  The tarball named here is NOT
			deleted, but any tarballs within this tarball will be expanded
			and their tarball deleted. """
		errors = []
		if not where:
			# Peel off dull extentions until arrive reasonable dir name
			i = tarball.find( '.tar' )
			if i > -1:
				where = tarball[:k]
			elif tarball.lower().endswith( '.tgz' ):
				where = tarball[:-4]
		if not where:
			errors += [
				'cannot deduce wher to unpack {0}'.format( tarball )
			]
		else:
			where = os.path.join(
				self.variant.prefix,
				where,
			)
			self._chatter(
				'Creating result tree {0}'.format( where )
			)
			cmd = [
				'/bin/mkdir',
				'-p',
				where
			]
			results = self._run( cmd ) # We can ignore these results
			problems = self._do_untar( tarball, where )
			if problems:
				errors += problems
			else:
				if self.perms:
					problems = self._do_chmod( where )
					if problems:
						errors += problems
				if self.variant.explode:
					problems = self._explode_dat( where )
					if problems:
						errors += problems
				self._chatter(
					'Processing extracted dir {0}'.format( where )
				)
				problems = self.process( where )
				if problems:
					errors += problems
		return errors if len(errors) else None

	def	report( self ):
		# print '[ E N D ]'
		return


if __name__ == '__main__':
	from	optparse	import	OptionParser
	prog, _ = os.path.splitext(
		os.path.basename( sys.argv[0] )
	)
	version  = '1.0.4'
	ua       = UnpackAll( variant = prog )
	variants = ua.get_variants()
	class	UntarParser( OptionParser ):
		def	format_epilog( self, formatter ):
			return self.epilog
	ua = None
	p = UntarParser(
		prog    = prog,
		version = 'v{0}'.format( version ),
		usage   = '{0} [options] [tar ..]'.format( prog ),
		epilog = '\n'.join(
			[ '', 'The available variants are:' ] +
			[ '    {0}'.format( v ) for v in sorted( variants ) ] +
			[ '' ],
		),
	)
	p.add_option(
		'-a',
		'--alias',
		dest = 'only_alias',
		default = False,
		action = 'store_true',
		help = 'list aliases, one per line, and exit'
	)
	p.add_option(
		'-l',
		'--list',
		dest    ='verbose',
		default = False,
		action  = 'store_true',
		help    = 'list individual files extracted from a tar(1) archive'
	)
	p.add_option(
		'-m',
		'--md5',
		dest = 'want_md5',
		default = False,
		action = 'store_true',
		help = 'use .md5 files to validate extracted files'
	)
	p.add_option(
		'-n',
		'--dry-run',
		dest = 'dry_run',
		default = False,
		action = 'store_true',
		help = "show what would be done but don't do it"
	)
	p.add_option(
		'-p',
		'--perms',
		dest    ='perms',
		action  = 'store_true',
		default = False,
		help    = 'alter permissions: d=0777, f=0660'
	)
	p.add_option(
		'-r',
		'--role',
		dest    ='role',
		metavar = 'ROLE',
		default = prog,
		help    = 'personality; default is "{0}"'.format( prog )
	)
	p.add_option(
		'-u',
		'--umask',
		dest    ='umask',
		metavar = 'NUM',
		type    = int,
		default = 0,
		help    = 'umask(2) value'
	)
	p.add_option(
		'-v',
		'--verbose',
		dest = 'verbose',
		default = False,
		action = 'store_true',
		help = 'announce actions being taken'
	)
	opts,candidates = p.parse_args()
	try:
		# Set a umask(2) to mitigate our default permissions, which are
		# set to 0777 for all files because this mimics ISDE's misbehavior.
		os.umask( opts.umask )
	except Exception, e:
		raise e(
			'cannot set umask({0})'.format( opts.umask )
		)
	ua = UnpackAll( variant = opts.role, verbose = opts.verbose )
	if opts.only_alias:
		for variety in ua.get_variants():
			print '{0}'.format( variety )
		exit( 0 )
	ua.set_md5_check( opts.want_md5 )
	if len(candidates) == 0:
		candidates = [ '.' ]
	opts.candidates = candidates
	for candidate in opts.candidates:
		# Take care not to delete top-level files but we will
		# delete any successfully-extracted archives that are
		# found in the exploded contents under this top-level.
		err = ua.process( candidate, cleanup = False )
		if err:
			ua.print_lines( err, is_err = True )
	ua.report()
	exit( 0 )
