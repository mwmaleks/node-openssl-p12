/**
 * Created by mwmaleks on 23.12.13.
 */

var   spawn =   require('child_process').spawn
    , _ =       require('underscore.deferred')
    , fs =      require('fs')
    , path =    require('path')
    , dirPath = path.join( process.cwd(), 'ssl')
    ;


exports.createClientSSL = createClientSSL;

/**
 * Generically createClientSSL
 *
 * @param {Object}  options The parameters to pass to createClientSSL
 * @param {Number} [options.bitSize] Bit size to use for generating a new key (defaults to 2048)
 * @param {String} [options.clientFileName] Client certificate file name (defaults to 'client001')
 * @param {String} [options.C] CSR country field (defaults to 'Example')
 * @param {String} [options.ST] CSR state field (defaults to 'Example')
 * @param {String} [options.L] CSR locality field (defaults to 'Example')
 * @param {String} [options.O] CSR organization field (defaults to 'Example')
 * @param {String} [options.OU] CSR organizational unit field (defaults to 'Example')
 * @param {String} [options.CN] CSR common name field (defaults to 'Example')
 * @param {String} [options.emailAddress] CSR email address field (defaults to 'example@example.ex')
 * @param {String} [options.clientPass] Clients' password to encrypt PKS12 (.p12) file (defaluts to q1w2e3r4t5y6)
 * @param {String} [options.caFileName] CA files name (without extension), both files key and certificate should exist (defaults to ca)
 * @param {String} [options.serial] Client certificate serial number (defaults to '01')
 * @param {Number} [options.days] Client certificate valid period (defaults to 365)
 * @param {Boolean}[options.isEncryptionRequired] Client certificate '-des3' encryption (defaults to false)
 *
 */
function createClientSSL(options) {

    var opt = getOptions.apply( this, arguments ) ;

    if ( !fs.existsSync( dirPath ) )
        fs.mkdirSync( dirPath );

    if ( opt.clientFileName == null )
        throw 'clientFileName not provided';


    return createClientKey(options)
        .then( createCSR )
        .then( createClientCRT )
        .then( createPKS12 )
        .then( getFingerprint );
}


function _path(fileName) { return path.join( dirPath, fileName ) }

function isObject(obj) {
    return Object.prototype.toString.call(obj) === '[object Object]';
}

function isBool(bool) {
    return Object.prototype.toString.call(bool) === '[object Boolean]';
}

function getOptions(options) {
    var defaultOptions = {
        bitSize: 2048,
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

    options = isObject(options) ? options : {};

    for (var param in defaultOptions) {
        if (defaultOptions.hasOwnProperty(param))
            options[param] = options[param] != null ? options[param] : defaultOptions[param];
    }

    return options;
}

var spawnOpenSSL = function( params ) {

    var   openssl = spawn( 'openssl', params, {
            cwd: dirPath,
            env: process.env,
            customFds: [-1, -1, -1],
            setsid: false
          })
        , stdout = ''
        , stderr = ''
        , deferredSpawnOpenSSL = _.Deferred()
        , countExit = 2
        ;

    openssl.stdout.on('data', function (data) {
        stdout += (data || '').toString();
    });

    openssl.stderr.on('data', function (data) {
        stderr += (data || '').toString();
    });

    openssl.on('exit', function (code) {
        if (--countExit === 1)
            return;

        deferredSpawnOpenSSL.reject(
            new Error('Invalid openssl exit code: ' + code + '\n% openssl ' + params.join(' ') + '\n' + stderr)
            , code
        );
    });

    openssl.on('close', function () {
        stdout = new Buffer( stdout, 'binary' ).toString('utf-8');
        stderr = new Buffer( stderr, 'binary' ).toString('utf-8');
        deferredSpawnOpenSSL.resolve( stdout, stderr );
    });

    return deferredSpawnOpenSSL;
};

var execOpenSSL = function( params, options ) {

    var deferredExecOpenSSL = _.Deferred();

    spawnOpenSSL(params).done(function( stdout ) {

        if ( params.indexOf('-fingerprint') !== -1 ) {

            var _fingerprint = stdout.match(/Fingerprint=([0-9a-fA-F:]+)$/m);

            if ( _fingerprint ) {
                deferredExecOpenSSL.resolve( options, _fingerprint[1] );
            } else {
                deferredExecOpenSSL.reject( new Error('No fingerprint got') );
            }

        } else
            deferredExecOpenSSL.resolve(options);

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
    params.push('-out', options.clientFileName + '.key', options.bitSize);

//      create key
    return execOpenSSL( params , options );
};

var createCSR =  function(options) {


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

var createPKS12 = function(options) {

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

var getFingerprint = function(options) {

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