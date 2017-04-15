#!/usr/bin/python
# vim: filetype=python noet sw=4 ts=4

import	sys
import	os
import	subprocess
import	traceback
import	re
import	stat

class	UnpackAll( object ):

	def	__init__( self, variant = 'unvmpinfo', verbose = 0, perms = False ):
		self.perms = perms
		self.variants = dict(
			default = dict(
				prefix  = 'DUNNO',
				glob    = re.compile( r'.*' ),
				explode = True
			),
			unsos = dict(
				prefix  = 'SOS',
				glob    = re.compile( r'.*tar.*' ),
				explode = True
			),
			unvmpinfo = dict(
				prefix  = 'VMPINFO',
				glob    = re.compile( r'.*vmpinfo.*tar.*' ),
				explode = True
			),
			untar = dict(
				prefix  = 'UNTAR',
				glob    = re.compile( r'.*tar.*' ),
				explode = True
			),
		)
		self.exploders = dict(
			xz  = 'J',
			bz2 = 'j',
			gz  = 'z'
		)
		self.set_variant( variant )
		return

	def	get_variants( self ):
		return self.variants

	def	set_variant( self, arg0 = 'default' ):
		prog, ext    = os.path.splitext( arg0 )
		if prog not in self.variants:
			prog = 'default'
		self.prefix  = self.variants[prog].get('prefix', 'UNPACKED' )
		self.explode = self.variants[prog].get('explode', True )
		self.glob    = self.variants[prog].get('glob', r'.*tar.*' )
		return

	def	scandir( self, dirname = '.' ):
		candidates = []
		err = None
		print 'glob = {0}'.format( self.glob.pattern )
		try:
			for entry in sorted( os.listdir( dirname ) ):
				print 'considered {0}'.format( entry )
				mo = self.glob.search( entry )
				if mo:
					print mo.groups()
					candidates.append( entry )
		except Exception, e:
			candidates = None
			err = traceback.format_exc()
		print 'located {0}'.format( candidates )
		return candidates, err

	def	do_cmd( self, cmd, show = True ):
		cli = ' '.join( cmd )
		print '  {0}'.format( cli )
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
		return msg, err

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
			msg, err = self.do_cmd( cmd, show = False )
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
						msg, err = self.do_cmd( cmd )
						if not err:
							try:
								os.unlink( name )
							except:
								pass
					else:
						root = name.find( '.tar' )
						if root < 0: continue
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
			self.prefix,
			root
		)
		try:
			os.makedirs( where )
		except:
			pass
		if self.do_tar( fn, where ):
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
						os.chmod( pn, 0666 )
					except Exception, e:
						pass
		return

	def	report( self ):
		pass


if __name__ == '__main__':
	from	optparse	import	OptionParser
	prog = os.path.splitext(
		os.path.basename( sys.argv[0] )
	)[0]
	version = '1.0.0'
	ua = UnpackAll( variant = prog )
	variants = '", "'.join( ua.get_variants() )
	ua = None
	p = OptionParser(
		prog    = prog,
		version = version,
		usage   = '{0} [options] [tar ..]'.format( prog ),
		epilog = 'The available variants are "{0}".'.format( variants )
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
	opts,candidates = p.parse_args()
	ua = UnpackAll( variant = opts.role, verbose = opts.verbose )
	if len(candidates) == 0:
		candidates, err = ua.scandir()
		if err:
			print >>sys.stderr, err
			print >>sys.stderr, "No arguments and no candidates found."
			exit( 1 )
	opts.candidates = candidates
	for candidate in opts.candidates:
		ua.process( candidate )
	ua.report()
	exit( 0 )
