/**
 * Created by mwmaleks on 23.12.13.
 */

var   spawn =   require('child_process').spawn
    , _ =       require('underscore.deferred')
    , fs =      require('fs')
    , rootDir = process.cwd()
    , path =    require('path')
    , options = {
        bitSize: 4096
        , isEncryptionRequired: true
    };

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

var execOpenSSL = function( params, action ) {

    var deferredExecOpenSSL = _.Deferred();

    spawnOpenSSL(params).done( function( code, stdout, stderr) {

//      так тоже не отправляется результат
        if (action.match(/createClientKey|createCSR|createCSR|createClientCRT|createPKS12/gim)) {
            deferredExecOpenSSL.resolve(stdout);
            return;
        }

        if ( action.match('getFingerprint') ) {

            var _fingerprint = stdout.match(/Fingerprint=([0-9a-fA-F:]+)$/m);

            console.log('_fingerprint = ', _fingerprint[1]);

            if ( _fingerprint ) {

                getFingerprint.fingerprint = _fingerprint[1];
//                почему-то оправляя тут результат в done я получаю undefined
                deferredExecOpenSSL.resolve( '---', _fingerprint[1] );
            } else {
                deferredExecOpenSSL.reject( new Error('No fingerprint got') );
            }
        }

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

var  createClientKey  = function() {

    var opt = getOptions.apply(this, arguments)
        , dirPath = path.join(rootDir, 'ssl')
        , deferred_exit = _.Deferred()
        , params = [ 'genrsa' ]
        , isCertFilesExists;

    opt.bitSize = opt.clientFileName != null
        ? opt.clientFileName
        : options.clientFileName;

    opt.bitSize = opt.bitSize != null
        ? opt.bitSize
        : options.bitSize;

    opt.isEncryptionRequired  = opt.isEncryptionRequired != null
        ? opt.isEncryptionRequired
        : options.isEncryptionRequired;

    if (opt.clientFileName == null)
        throw 'clientFileName already exists';

    //  check in 'ssl' folder exists, if not crate it
    if ( !fs.existsSync(dirPath) )
        fs.mkdirSync(dirPath);

    //  check if clientFileName already used
    isCertFilesExists = ['.key', '.crt', '.p12' ].reduce(function(accum, item) {
        accum = isBool(accum) ? accum : true;
        return accum && fs.existsSync( path.join( dirPath, opt.clientFileName + item ) );
    });

    if ( isCertFilesExists )
        throw opt.clientFileName + ' already exists';

//      create key
    opt.isEncryptionRequired && params.push('-des3');

    params.push('-out', opt.clientFileName + '.key');

    execOpenSSL(params , 'createClientKey')
        .done(function() {
            deferred_exit.resolve();
        })
        .fail(function(err) {
            deferred_exit.reject(err);
        });

    return deferred_exit;
};

var createCSR =  function() {

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
    ], 'createCSR');
};

var createClientCRT = function() {

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

    ], 'createCSR');
};

var createPKS12 = function() {

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

    ], 'createPKS12')
};

var getFingerprint = function() {

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

    ], 'getFingerprint' );
};

var createClientSSL = function(opt) {

    options = opt;

    var   deferred = _.Deferred();
    createClientKey(opt)
        .done( function() {

        createCSR()
            .done( function() {

            createClientCRT()
                .done( function() {

                createPKS12()
                    .done( function() {

                    getFingerprint()
                        .done( function() {

                        getFingerprint()
                            .done( function() {

//                            TODO solve the issue with deferred resolve to send the result properly
                            deferred.resolve( getFingerprint.fingerprint );
                        })
                        .fail(function(err) {
                                deferred.reject(err);
                        });
                    })
                    .fail(function(err) {
                        deferred.reject(err);
                    });
                })
                .fail(function(err) {
                    deferred.reject(err);
                });
            })
            .fail(function(err) {
                deferred.reject(err);
            });
        })
        .fail(function(err) {
            deferred.reject(err);
        });
    })
    .fail( function(err) {
        deferred.reject(err);
    });
    return deferred;
};

exports.createClientKey      = createClientKey;
exports.createCSR            = createCSR;
exports.createClientCRT      = createClientCRT;
exports.createPKS12          = createPKS12;
exports.getFingerprint       = getFingerprint;
exports.createClientSSL      = createClientSSL;