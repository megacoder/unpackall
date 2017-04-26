#!/usr/bin/python
# vim: filetype=python noet sw=4 ts=4

import	hashlib
import	os
import	re
import	stat
import	subprocess
import	sys
import	traceback

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
			glob    = re.compile( r'.*' ),
			explode = True,
			md5     = True,
			info    = 'anonymous tarball'
		),
		unosw = AttrDict(
			prefix  = 'UNOSW',
			glob    = re.compile( r'osw.*tar.*' ),
			explode = True,
			md5     = True,
			info    = 'OSWatcher tarball'
		),
		unarchive = AttrDict(
			prefix	= 'ARCHIVE',
			glob    = re.compile( r'.*tar.*' ),
			explode = True,
			md5		= True,
			info	= 'OSWatcher archives'
		),
		unsos = AttrDict(
			prefix  = 'SOS',
			glob    = re.compile( r'sosreport.*tar.*' ),
			explode = True,
			md5		= True,
			info	= 'SOSREPORT archives'
		),
		unvmpinfo = AttrDict(
			prefix  = 'VMPINFO',
			glob    = re.compile( r'.*vmpinfo.*tar.*' ),
			explode = True,
			md5		= True,
			info	= 'VMPINFO3 archive'
		),
		untar = AttrDict(
			prefix  = 'UNTAR',
			glob    = re.compile( r'.*tar.*' ),
			explode = True,
			md5		= True,
			info	= 'generic tar(1) archive'
		),
	)

	def	__init__( self, variant = 'untar', verbose = False, perms = False ):
		self.set_verbose( verbose )
		self.perms    = perms
		self.set_variant( variant )
		return

	def	get_variants( self ):
		key_width = max(
			map(
				len,
				UnpackAll.VARIANTS.keys()
			)
		) + 1
		prefix_width = max(
			map(
				len,
				[ UnpackAll.VARIANTS[key].prefix for key in UnpackAll.VARIANTS ]
			)
		)
		fmt = '{{0:>{0}}}  {{1:<{1}}}  {{2}}'.format(
			key_width,
			prefix_width
		)
		for key in sorted( UnpackAll.VARIANTS ):
			v = UnpackAll.VARIANTS[key]
			yield fmt.format(
				key + ':',
				v.prefix,
				v.info,
			)
		return

	def	set_variant( self, arg0 = 'default' ):
		prog, ext    = os.path.splitext( arg0 )
		if prog not in UnpackAll.VARIANTS:
			prog = 'default'
		self.variant = UnpackAll.VARIANTS[prog]
		return

	def	set_md5_check( self, want = True ):
		self.variant.md5 = want

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
			raise ValueError
		return

	def	get_verbose( self ):
		return self.verbose

	def	is_verbose( self, needed = 1 ):
		return True if self.verbose >= needed else False

	def	_chatter( self, s ):
		if self.is_verbose():
			print s
		return

	def	scandir( self, dirname = '.' ):
		candidates = []
		err = None
		try:
			for entry in sorted( os.listdir( dirname ) ):
				mo = self.variant.glob.search( entry )
				if mo:
					candidates.append( entry )
		except Exception, e:
			candidates = None
			err = traceback.format_exc()
		self._chatter( 'scanned "{0}", found candidates "{1}"'.format(
			dirname,
			candidates
		) )
		return err, candidates

	def	do_cmd( self, cmd, show = True ):
		if self.is_verbose():
			cli = ' '.join( cmd )
			self._chatter( '  {0}'.format( cli ) )
		try:
			p = subprocess.Popen(
				cmd,
				bufsize = (32 * 1024 ),
				stdout = subprocess.PIPE,
				stderr = subprocess.PIPE
			)
			msg, err = p.communicate()
			if len(err) == 0:
				err = None
		except Exception, e:
			msg = None
			err = traceback.format_exc()
		if show:
			if err and len(err)>0:
				for line in err.splitlines():
					print '  *** {0}'.format( err )
			if msg and len(msg) > 0:
				for line in msg.splitlines():
					print '  {0}'.format( line )
		return err, msg

	def	do_tar( self, tn, where ):
		worked = False
		for method in [ 'a', 'z', 'j', 'J' ]:
			cmd = [
				'/bin/tar',
				'-C',
				where,
				'-m',
				'-x{0}f'.format( method ),
				tn
			]
			err, msg = self.do_cmd( cmd, show = False )
			if not err:
				worked = True
				break
		if not worked:
			print '  *** Could not unpack {0} archive.'.format( tn )
		return worked

	def	subtree( self, dirname, discard = False ):
		""" Traverse subtree 'dn' looking for tarballs to expand.  Do this
			as long as new tarballs or zipfiles  are found.  Delete the
			tarball/zipfile if allowed by the 'keep' parameter. """
		# Explode any tarballs we find in this directory
		rescan = True
		while rescan:
			self._chatter( 'Scanning subtree {0}'.format( dirname ) )
			rescan = False
			for entry in sorted( os.listdir( dirname ) ):
				name = os.path.join( dirname, entry )
				# print '  + {0}'.format( name )
				if os.path.isdir( name ):
					self.subtree( name, discard = True )
				elif os.path.isfile( name ):
					# Begin with the filename extension
					where, ext = os.path.splitext( name )
					if name.endswith( '.zip' ):
						self._chatter(
							'Detected ZIP file {0}'.format( name )
						)
						try:
							os.makedirs( where )
						except:
							pass
						cmd = [
							'/bin/unzip',
							'-s',
							'-u',
							name
						]
						err, msg = self.do_cmd( cmd )
						if not err:
							try:
								os.unlink( name )
							except:
								pass
					else:
						root = name.find( '.tar' )
						if root < 0: continue
						self._chatter(
							'Detected tar archive {0}'.format( name )
						)
						where = name[:root]
						try:
							os.makedirs( where )
						except:
							pass
						if self.do_tar( name, where ):
							rescan = True
						try:
							os.unlink( name )
						except Exception, e:
							# Avoid endless loop unpacking
							rescan = False
		return

	def	process( self, fn ):
		""" Explode tarball 'fn' and expand the resulting directory tree
			for other tarballs to expand.  The tarball named here is NOT
			deleted, but any tarballs within this tarball will be expanded
			and their tarball deleted. """
		root = os.path.basename( fn )
		ext = root.find( '.tar' )
		if ext == -1:
			print >>sys.stderr, 'Not a tarball: {0}'.format( fn )
			return
		root = root[:ext]
		where = os.path.join(
			self.variant.prefix,
			root
		)
		try:
			self._chatter(
				'Creating result tree {0}'.format( where )
			)
			os.makedirs( where )
		except:
			pass
		if self.do_tar( fn, where ):
			self._chatter(
				'Processing extracted subtree {0}'.format( where )
			)
			self.subtree( where )
		if self.perms:
			try:
				os.umask( 0 )
			except Exception, e:
				print >>sys.stderr, 'Cannot set umask'
				print >>sys.stderr, traceback.format_exc()
			for rootdir,dirs,files in os.walk( where ):
				# Change directories first
				perm = (
					stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC |
					stat.S_IRGRP | stat.S_IWGRP  | stat.S_IXGRP |
					stat.S_IROTH | stat.S_IWOTH  | stat.S_IXOTH |
					0
				)
				for name in sorted( dirs ):
					pn = os.path.join( rootdir, name )
					sehf._chatter(
						'Setting new dir permissions {0}: {1:04o}'.format(
							pn,
							perm
						)
					)
					try:
						os.chmod( pn, perm )
					except Exception, e:
						pass
				# Change files last
				perm = (
					stat.S_IREAD | stat.S_IWRITE |
					stat.S_IRGRP | stat.S_IWGRP  |
					stat.S_IROTH | stat.S_IWOTH  |
					0
				)
				for name in sorted( files ):
					pn = os.path.join( rootdir, name )
					try:
						self._chatter(
							'File {0} new permissions: {1:04o}'.format(
								pn,
								perm
							)
						)
						os.chmod( pn, perm )
					except Exception, e:
						pass
		if self.variant.md5:
			self._chatter( 'Scanning for MD5 checksum files.' )
			for rootdir,dirs,files in os.walk( where ):
				mf5sums = [
					f for f in files if f.endswith( '.md5' )
				]
				for md5sum in md5sums:
					err = True
					output = '*** MD5SUM mismatch ***'
					realfile, _ = os.path.splitext( file )
					real_fn = os.path.join(
						rootdir,
						realfile
					)
					self._chatter(
						'Checking {0}'.format( real_fn )
					)
					hash = hashlib.md5()
					with open( real_fn, 'rb' ) as f:
						for chunk in iter( f.read, 4096 ):
							hash.update( chunk )
					calc_hash = hash.hexdigest()
					md5_fn = os.path.join(
						rootdir,
						md5sum
					)
					with open( md5_fm ) as f:
						tokens = f.readline().split()
						self._chatter(
							'File {0}: calc[{1}], real[{2}]'.format(
								md5_fn,
								calc_hash,
								tokens[0]
							)
						)
						if len(tokens) and tokens[0] == calc_hash:
							err = False
					if err:
						print '  *** {0}'.format(
							'MD5 checksum not verified: "{0}"'.format(
								os.path.join(
									rootdir,
									realfile
							   )
						   )
					   )
		if self.variant.explode:
			self._chatter(
				'Scanning subtree {0} for compressed files.'.format(
					where
				)
			)
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
					'--keep',
					'--quiet',
					'--',
				],
			})
			for rootdir,dirs,files in os.walk( where ):
				cmd = None
				for file in files:
					for suffix in suffixes:
						if file.endswith( suffix ):
							cmd = suffixes[suffix] + [
								os.path.join( where, file )
							]
							break
				if cmd:
					err = True
					try:
						output = self.do_cmd( cmd )
						err = False
					except subprocess.CalledProcessError, e:
						output = e.output
					except Exception, e:
						print >>sys.stderr, 'Cannot uncompress {0}'.format(
							os.path.join( where, file )
						)
						raise e
					if err:
						self.show_output( err, output )
		return

	def	report( self ):
		pass


if __name__ == '__main__':
	from	optparse	import	OptionParser
	prog = os.path.splitext(
		os.path.basename( sys.argv[0] )
	)[0]
	version  = '1.0.0'
	ua       = UnpackAll( variant = prog )
	variants = ua.get_variants()
	class	UntarParser( OptionParser ):
		def	format_epilog( self, formatter ):
			return self.epilog
	ua = None
	p = UntarParser(
		prog    = prog,
		version = version,
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
		'-v',
		'--verbose',
		dest = 'verbose',
		default = False,
		action = 'store_true',
		help = 'announce actions being taken'
	)
	opts,candidates = p.parse_args()
	if opts.only_alias:
		for variety in variants:
			print '{0}'.format( variety )
		exit( 0 )
	ua = UnpackAll( variant = opts.role, verbose = opts.verbose )
	ua.set_md5_check( opts.want_md5 )
	if len(candidates) == 0:
		err, candidates = ua.scandir()
		if err:
			print >>sys.stderr, err
			print >>sys.stderr, "No arguments and no candidates found."
			exit( 1 )
	opts.candidates = candidates
	for candidate in opts.candidates:
		ua.process( candidate )
	ua.report()
	exit( 0 )
