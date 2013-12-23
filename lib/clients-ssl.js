/**
 * Created by mwmaleks on 23.12.13.
 */

var   spawn =   require('child_process').spawn
    , _ =       require('underscore.deferred')
    , fs =      require('fs')
    , rootDir = process.cwd()
    , path =    require('path')
    , dirPath = path.join(rootDir, 'ssl')
    ;


function isObject(obj) {
    return Object.prototype.toString.call(obj) === '[object Object]';
}

function isBool(bool) {
    return Object.prototype.toString.call(bool) === '[object Boolean]';
}

function getOptions() {
    return arguments.length > 0 && isObject(arguments[0]) ? arguments[0] : options;
}

var spawnOpenSSL = function( params ) {

    var   openssl = spawn( 'openssl', params, {
            cwd: path.join( rootDir, 'ssl'),
            env: process.env,
            customFds: [-1, -1, -1],
            setsid: false
          })
        , needed = 2  // wait for both exit and close.
        , code = -1
        , bothDone
        , stdout = ''
        , stderr = ''
        , deferredSpawnOpenSSL = _.Deferred();

    openssl.stdout.on('data', function (data) {
        stdout += (data || '').toString('binary');
    });

    openssl.stderr.on('data', function (data) {
        stderr += (data || '').toString('binary');
    });

    // We need both the return code and access to all of stdout.  Stdout isn't
    // *really* available until the close event fires; the timing nuance was
    // making this fail periodically.

    bothDone = function() {
        if (code) {
            deferredSpawnOpenSSL.reject(
                new Error('Invalid openssl exit code: ' + code + '\n% openssl ' + params.join(' ') + '\n' + stderr)
                , code
            );
        } else
            deferredSpawnOpenSSL.resolve( code, stdout, stderr );
    };

    openssl.on( 'exit', function (ret) {
        code = ret;
        ( --needed < 1 ) && bothDone();
    });

    openssl.on( 'close', function () {
        stdout = new Buffer( stdout, 'binary' ).toString('utf-8');
        stderr = new Buffer( stderr, 'binary' ).toString('utf-8');
        ( --needed < 1 ) && bothDone();
    });

    return deferredSpawnOpenSSL;
};

var execOpenSSL = function( params, options ) {

    var deferredExecOpenSSL = _.Deferred();

    spawnOpenSSL(params).done( function( code, stdout, stderr) {

        if (params.indexOf('-fingerprint')) {
            var _fingerprint = stdout.match(/Fingerprint=([0-9a-fA-F:]+)$/m);

            console.log('_fingerprint = ', _fingerprint[1]);

            if ( _fingerprint ) {
                deferredExecOpenSSL.resolve(params, options, stdout, _fingerprint[1] );
            } else {
                deferredExecOpenSSL.reject( new Error('No fingerprint got') );
            }
        } else
            deferredExecOpenSSL.resolve(params, options, stdout);

    })
    .fail( function(err) {
        deferredExecOpenSSL.reject(err);
    });
    return deferredExecOpenSSL;
};

var generateCSRSubject = function() {

    var csrData = {
            C: options.country || options.C || '',
            ST: options.state || options.ST || '',
            L: options.locality || options.L || '',
            O: options.organization || options.O || '',
            OU: options.organizationUnit || options.OU || '',
            CN: options.commonName || options.CN || 'localhost',
            emailAddress: options.emailAddress || ''
        }
        , csrBuilder = [];

    Object.keys(csrData).forEach( function(key) {
        if ( csrData[key] ) {
            csrBuilder.push( '/' + key + '=' + csrData[key].replace(/[^\w \.\-@]+/g, ' ').trim() );
        }
    });

    return csrBuilder.join('');
};

var  createClientKey  = function(p , options) {

    var  dirPath = path.join(rootDir, 'ssl')
        , isCertFilesExists
        , params =  [ 'genrsa' ];

    //  check if clientFileName already used
    isCertFilesExists = ['.key', '.crt', '.p12' ].reduce(function(accum, item) {
        accum = isBool(accum) ? accum : true;
        return accum && fs.existsSync( path.join( dirPath, opt.clientFileName + item ) );
    });

    if ( isCertFilesExists )
        throw options.clientFileName + ' already exists';

//      create key
    options.isEncryptionRequired && params.push('-des3');

    params.push('-out', opt.clientFileName + '.key');

    return execOpenSSL(params , options);
};

var createCSR =  function(params , options) {

    var opt = getOptions.apply(this, arguments);

        opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;

    if ( !fs.existsSync( path.join( rootDir, 'ssl', opt.clientFileName + '.key')))
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
    ], options);
};

var createClientCRT = function(params , options) {

    var opt = getOptions.apply(this, arguments);
    opt.caFileName = opt.caFileName ? opt.caFileName : options.caFileName;
    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;
    opt.serial = opt.serial ? opt.serial : '02';

    var isFileExists
        , _path = function(fileName) { return path.join( rootDir, 'ssl', fileName) };

    isFileExists = fs.existsSync( _path(opt.caFileName + '.crt'))
        && fs.existsSync( _path(opt.caFileName + '.key'))
        && fs.existsSync( _path(opt.clientFileName + '.key'));

    if ( isFileExists )
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

    ], options);
};

var createPKS12 = function(params, options) {

    var opt = getOptions.apply(this, arguments);
    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;
    opt.clientPass = opt.clientPass ?opt.clientPass :options.clientPass;

    var isFileExists;

    var _path = function(fileName) { return path.join( rootDir, 'ssl', fileName) };

    isFileExists = fs.existsSync( _path( opt.clientFileName + '.crt') )
        && fs.existsSync( _path( opt.clientFileName + '.key') )
        && fs.existsSync( _path( opt.caFileName + '.crt'));

    if (isFileExists)
        throw 'file is exists ' + opt.clientFileName + '.crt or '
            + opt.clientFileName + '.key or '
            + opt.caFileName + '.crt';

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

var getFingerprint = function(params, options) {

    var opt = getOptions.apply(this, arguments);

    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;

    if ( fs.existsSync( path.join( rootDir, 'ssl', opt.clientFileName + '.crt')) )
        throw 'file ' + opt.clientFileName + '.crt is exists!' ;

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

    options.bitSize = options.bitSize || 4096;
    options.isEncryptionRequired = isBool(options.isEncryptionRequired) && !!options.isEncryptionRequired;

    // вот тут надо папку делать
    if ( !fs.existsSync(dirPath) )
        fs.mkdirSync(dirPath);

    if (options.clientFileName == null)
        throw 'clientFileName already exists';


    return createClientKey(options)
        .then(createCSR)
        .then(createClientCRT)
        .then(createPKS12)
        .then(getFingerprint);

    // next .done(function(fingerprint) { ... });
};

exports.createClientSSL      = createClientSSL;