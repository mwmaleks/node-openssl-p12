/**
 * Created by mwmaleks on 23.12.13.
 */

var   spawn =   require('child_process').spawn
    , _ =       require('underscore.deferred')
    , fs =      require('fs')
    , path =    require('path')
    , dirPath = path.join( process.cwd(), 'ssl')
    ;

function _path(fileName) { return path.join( dirPath, fileName ) }

function isObject(obj) {
    return Object.prototype.toString.call(obj) === '[object Object]';
}

function isBool(bool) {
    return Object.prototype.toString.call(bool) === '[object Boolean]';
}

function getOptions(options) {
    var defaultOptions = {
        bitSize: 4096,
        clientFileName :'client001',
        C:'EX',
        ST: 'Example',
        L: 'Example',
        O: 'Example',
        OU: 'Example',
        CN: 'Example',
        emailAddress: 'example@example.ex',
        clientPass: 'q1w2e3r4t5y6',
        caFileName: 'ca',
        serial: '01',
        days: 365,
        isEncryptionRequired : false
    };
    return isObject(options) ? {
        bitSize: options.bitSize,
        clientFileName: options.clientFileName,
        C: options.country || options.C || defaultOptions.C,
        ST: options.state || options.ST || defaultOptions.ST,
        L: options.locality || options.L || defaultOptions.L,
        O: options.organization || options.O || defaultOptions.O,
        OU: options.organizationUnit || options.OU || defaultOptions.OU,
        CN: options.commonName || options.CN || defaultOptions.CN,
        emailAddress: options.emailAddress || defaultOptions.emailAddress,
        clientPass: options.clientPass || defaultOptions.clientPass,
        caFileName: options.caFileName || defaultOptions.caFileName,
        serial: options.serial|| defaultOptions.serial,
        days: options.days || defaultOptions.days,
        isEncryptionRequired : options.isEncryptionRequired || defaultOptions.isEncryptionRequired
    } : defaultOptions;
}

var spawnOpenSSL = function( params ) {

    var   openssl = spawn( 'openssl', params, {
            cwd: dirPath,
            env: process.env,
            customFds: [-1, -1, -1],
            setsid: false
          })
        , code = -1
        , stdout = ''
        , stderr = ''
        , deferredSpawnOpenSSL = _.Deferred()
        ;

    openssl.stdout.on('data', function (data) {
        stdout += (data || '').toString();
    });

    openssl.stderr.on('data', function (data) {
        stderr += (data || '').toString();
    });

    var   deferredOnExit  = _.Deferred()
        , deferredOnClose = _.Deferred()
        ;

    openssl.on( 'exit', function (code) {
        deferredOnExit.resolve(code);
    });

    openssl.on( 'close', function () {
        stdout = new Buffer( stdout, 'binary' ).toString('utf-8');
        stderr = new Buffer( stderr, 'binary' ).toString('utf-8');
        deferredOnClose.resolve();
    });
    _.when( deferredOnExit, deferredOnExit).done( function() {
//      arguments = code from exit event
        if ( arguments[0] ) {
            deferredSpawnOpenSSL.reject(
                new Error('Invalid openssl exit code: ' + code + '\n% openssl ' + params.join(' ') + '\n' + stderr)
                , code
            );
        } else
            deferredSpawnOpenSSL.resolve( code, stdout, stderr );

    });

    return deferredSpawnOpenSSL;
};

var execOpenSSL = function( params, options ) {

    var deferredExecOpenSSL = _.Deferred();

    spawnOpenSSL(params).done( function( code, stdout, stderr) {

        if ( params.indexOf('-fingerprint') !== -1 ) {

            var _fingerprint = stdout.match(/Fingerprint=([0-9a-fA-F:]+)$/m);
            if ( _fingerprint ) {
                deferredExecOpenSSL.resolve( _fingerprint[1] );
            } else {
                deferredExecOpenSSL.reject( new Error('No fingerprint got') );
            }
        } else
            deferredExecOpenSSL.resolve( options );

    })
    .fail( function(err) {
        deferredExecOpenSSL.reject(err);
    });
    return deferredExecOpenSSL;
};

var generateCSRSubject = function(options) {

    var csrData = {
            C: options.C,
            ST: options.ST,
            L: options.L,
            O: options.O,
            OU: options.OU,
            CN: options.CN,
            emailAddress: options.emailAddress
        }
        , csrBuilder = []
        ;

    Object.keys(csrData).forEach( function(key) {
        if ( csrData[key] ) {
            csrBuilder.push( '/' + key + '=' + csrData[key].replace(/[^\w \.\-@]+/g, ' ').trim() );
        }
    });
    return csrBuilder.join('');
};

var  createClientKey  = function(options) {

    var   certFilesExist
        , params =  [ 'genrsa' ]
        ;

    //  check if clientFileName already used
    certFilesExist = ['.key', '.crt', '.p12' ].reduce( function(accum, item) {
        accum = isBool(accum) ? accum : false;
        return accum || fs.existsSync( _path( options.clientFileName + item ) );
    });

    if ( certFilesExist )
        throw options.clientFileName + ' already exists';

    options.isEncryptionRequired && params.push('-des3');
    params.push('-out', options.clientFileName + '.key');

//      create key
    return execOpenSSL( params , options );
};

var createCSR =  function( options ) {

    var opt = getOptions.apply( this, arguments )
        ;
    if ( !fs.existsSync( _path(opt.clientFileName + '.key')))
        throw 'there is no such keyFile :';

    return execOpenSSL( [
        'req',
        '-new',
        '-key',
        opt.clientFileName + '.key',
        '-subj',
        generateCSRSubject(opt),
        '-out',
        opt.clientFileName + '.csr'
    ], opt );
};

var createClientCRT = function(options) {
    
    var  opt = getOptions.apply( this, arguments)
        ,filesExist
        ;

    filesExist = fs.existsSync( _path(opt.caFileName + '.crt'))
        && fs.existsSync( _path(opt.caFileName + '.key'))
        && fs.existsSync( _path(opt.clientFileName + '.key'));

    if ( !filesExist )
        throw 'createClientCRT received wrong files';

    return execOpenSSL( [
        'x509',
        '-req',
        '-days',
        opt.days,
        '-in',
        opt.clientFileName + '.csr',
        '-CA',
        opt.caFileName + '.crt',
        '-CAkey',
        opt.caFileName + '.key',
        '-set_serial',
        opt.serial,
        '-out',
        opt.clientFileName + '.crt'

    ], opt);
};

var createPKS12 = function( params, options ) {

    var   opt = getOptions.apply( this, arguments )
        , filesExist
        ;

        filesExist = fs.existsSync( _path( opt.clientFileName + '.crt') )
        && fs.existsSync( _path( opt.clientFileName + '.key') )
        && fs.existsSync( _path( opt.caFileName + '.crt'));

    if ( !filesExist )
        throw 'some of ' + opt.clientFileName + '.crt or '
            + opt.clientFileName + '.key or '
            + opt.caFileName + '.crt not found';

    return execOpenSSL([
        'pkcs12',
        '-export',
        '-in',
        opt.clientFileName + '.crt',
        '-inkey',
        opt.clientFileName + '.key',
        '-certfile',
        opt.caFileName + '.crt',
        '-out',
        opt.clientFileName + '.p12',
        '-passout',
        'pass:' + opt.clientPass

    ], options)
};

var getFingerprint = function( params, options ) {

    var opt = getOptions.apply( this, arguments );

    if ( !fs.existsSync( _path( opt.clientFileName + '.crt')) )
        throw 'file ' + opt.clientFileName + '.crt not found' ;

    return execOpenSSL( [
        'x509',
        '-in',
        opt.clientFileName + '.crt',
        '-sha1',
        '-noout',
        '-fingerprint'
    ], options );
};

var createClientSSL = function(options) {

    var opt = getOptions.apply( this, arguments) ;

    if ( !fs.existsSync(dirPath) )
        fs.mkdirSync(dirPath);

    if ( opt.clientFileName == null )
        throw 'clientFileName not provided';


    return createClientKey(options)
        .then( createCSR )
        .then( createClientCRT )
        .then( createPKS12 )
        .then( getFingerprint );

    // next .done(function(fingerprint) { ... });
};

exports.createClientSSL = createClientSSL;