const watch = require( 'watch' )
const { basename, join } = require( 'path' )
const { unlinkSync, existsSync } = require( 'fs' )
const { compileContract } = require( 'scryptlib' )
const { glob } = require( 'glob' )

function compile_for ( file ) {
  const fileName = basename( file )
  if ( fileName.endsWith( '.scrypt' ) ) {
    try {
      clean_description_file( fileName )
      const input = join( __dirname, 'contracts', fileName )
      const out = join( __dirname, 'out' )

      console.log(input, out)
      compileContract( input, out )
    } catch ( error ) {
      console.log( error )
    }
  }
}

function clean_description_file ( fileName ) {
  if ( fileName.endsWith( '.scrypt' ) ) {
    try {
      const descFile = join( __dirname, 'out', fileName.replace( '.scrypt', '_desc.json' ) )
      if ( existsSync( descFile ) ) {
        unlinkSync( descFile )
      }
    } catch ( error ) {
      console.log( error )
    }
  }
}

if ( process.argv[ 2 ] === '--gen-desc' ) {
  glob( '**/*.scrypt', ( err, files ) => {
    if ( err ) return
    files.forEach( f => {
      compile_for( f )
    } )
  } )
} else {
  watch.watchTree( 'contracts', { interval: 2 }, function ( f, curr, prev ) {
    if ( typeof f === 'object' && prev === null && curr === null ) {
      // Finished walking the tree
      Object.keys( f ).forEach( ( file ) => {
        console.log( 'compile', file )
        compile_for( file )
      } )
    } else if ( prev === null ) {
      // f is a new file
    } else if ( curr.nlink === 0 ) {
      // f was removed
    } else {
      // f was changed
      compile_for( f )
    }
  } )
}
