/**
 * Created by mwmaleks on 23.12.13.
 */

var   spawn =   require('child_process').spawn
    , _ =       require('underscore')
    , fs =      require('fs')
    , rootDir = process.cwd()
    , path =    require('path')
    , options = {};
_.mixin( require('underscore.deferred'));
var spawnOpenSSL = function( params ) {

    var   openssl = spawn( 'openssl', params,
            { cwd: path.join( rootDir, 'ssl'),
                env: process.env,
                customFds: [-1, -1, -1],
                setsid: false
            })
        , stdout = ''
        , stderr = ''
        , _dfd_spawnOpenSSL = _.Deferred();

    openssl.stdout.on('data', function (data) {
        stdout += (data || '').toString('binary');
    });

    openssl.stderr.on('data', function (data) {
        stderr += (data || '').toString('binary');
    });

    // We need both the return code and access to all of stdout.  Stdout isn't
    // *really* available until the close event fires; the timing nuance was
    // making this fail periodically.
    var needed = 2;  // wait for both exit and close.
    var code = -1;
    var bothDone = function() {
        if (code) {
            _dfd_spawnOpenSSL.reject( new Error('Invalid openssl exit code: ' + code + '\n% openssl ' + params.join(' ') + '\n' + stderr), code );
        } else {
            _dfd_spawnOpenSSL.resolve( code, stdout, stderr );
        }
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
    return _dfd_spawnOpenSSL;
};

var execOpenSSL = function ( params, action ) {

    var _dfd_execOpenSSL = _.Deferred();

    spawnOpenSSL(params).done( function( code, stdout, stderr) {

//      так тоже не отправляется результат
        action.match('createClientKey') && _dfd_execOpenSSL.resolve.apply( _dfd_execOpenSSL, [stdout] );

        action.match('createCSR') && _dfd_execOpenSSL.resolve(stdout);
        action.match('createClientCRT') && _dfd_execOpenSSL.resolve(stdout);
        action.match('createPKS12') && _dfd_execOpenSSL.resolve(stdout);

        if ( action.match('getFingerprint') ) {

            var _fingerprint = stdout.match(/Fingerprint=([0-9a-fA-F:]+)$/m);

            console.log('_fingerprint = ', _fingerprint[1]);

            if ( _fingerprint ) {

                getFingerprint.fingerprint = _fingerprint[1];
//                почему-то оправляя тут результат в done я получаю undefined
                _dfd_execOpenSSL.resolve( '' );
            } else {
                _dfd_execOpenSSL.reject( new Error('No fingerprint got') );
            }
        }

    }).fail( function(err) {
            _dfd_execOpenSSL.reject(err);
        });
    return _dfd_execOpenSSL;
};

var generateCSRSubject = function() {

    var   options = arguments ? arguments[0] : {}
        , csrData = {
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

    var opt = arguments ? arguments[0] : options;
    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;
    opt.bitSize = opt.bitSize ? opt.bitSize : options.bitSize;
    opt.encryptionReqired  = opt.encryptionReqired ? opt.encryptionReqired : options.encryptionReqired;

//  check in 'ssl' folder exists, if not crate it
    ( !fs.existsSync( path.join(rootDir, 'ssl' ) ) ) && fs.mkdirSync( path.join( rootDir, 'ssl') );

//  check if clientFileName already used
    var _dfds = [];
    _.each( ['.key', '.crt', '.p12' ], function(item) {
        var _dfd = _.Deferred();

        fs.exists( path.join( rootDir, 'ssl', opt.clientFileName + item ), function(ex) {
            _dfd.resolve(ex);
        });
        _dfds.push(_dfd);
    });

    var _dfd_exit = _.Deferred();
    _.when.apply( _dfds, _dfds).done( function() {

        if ( _.any( arguments, function(arg) { return arg }) )  throw opt.clientFileName + ' already exists';

//      create key
        var params = [ 'genrsa'];
        opt.encryptionReqired && params.push('-des3');
        params.push( '-out',   opt.clientFileName + '.key');

        execOpenSSL(params , 'createClientKey' ).done( function() {
            _dfd_exit.resolve();
        }).fail( function(err) {
                _dfd_exit.reject(err);
            });
    });
    return _dfd_exit;
};

var createCSR =  function() {

    var opt = !_.isEmpty(arguments) ? arguments[0] : options;
    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;

    var _dfd_ex = _.Deferred();
    fs.exists( path.join( rootDir, 'ssl', opt.clientFileName + '.key'), function(ex) {

        if  ( !ex ) throw 'there is no such keyFile :';

        var params = [
            'req',
            '-new',
            '-key',
            opt.clientFileName + '.key',
            '-subj',
            generateCSRSubject(opt),
            '-out',
            opt.clientFileName + '.csr'
        ];
        return execOpenSSL( params, 'createCSR').done( function() {

            _dfd_ex.resolve();
        }).fail( function(err) {

                _dfd_ex.reject(err);
            });
    });

    return _dfd_ex;
};

var createClientCRT = function() {

    var opt = !_.isEmpty(arguments) ? arguments[0] : options;
    opt.caFileName = opt.caFileName ? opt.caFileName : options.caFileName;
    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;
    opt.serial = opt.serial ? opt.serial : '02';

    var   _dfd_crt  = _.Deferred()
        , _dfd_key  = _.Deferred()
        , _dfd_csr  = _.Deferred()
        , _dfd_exit = _.Deferred();
    var _path = function(fileName) { return path.join( rootDir, 'ssl', fileName) };

    fs.exists( _path(opt.caFileName + '.crt'), function(ex) {
        _dfd_crt.resolve(ex);
    });
    fs.exists( _path(opt.caFileName + '.key'), function(ex) {
        _dfd_key.resolve(ex);
    });
    fs.exists( _path(opt.clientFileName + '.key'), function(ex) {
        _dfd_csr.resolve(ex);
    });
    _.when( _dfd_crt, _dfd_key, _dfd_csr).done( function() {

        if ( _.any( arguments, function(arg) { return !arg }) )  throw 'createClientCRT received wrong files';

        var params = [
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

        ];
        execOpenSSL( params, 'createCSR').done( function() {
            _dfd_exit.resolve();
        }).fail( function(err) {
                _dfd_exit.reject(err);
            });


    }).fail(function(err) {
            _dfd_exit.reject(err);
        });
    return _dfd_exit;
};

var createPKS12 = function() {

    var opt = !_.isEmpty(arguments) ? arguments[0] : options;
    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;
    opt.clientPass = opt.clientPass ?opt.clientPass :options.clientPass;

    var   _dfd_crt      = _.Deferred()
        , _dfd_key      = _.Deferred()
        , _dfd_ca_crt   = _.Deferred()
        , _dfd_exit     = _.Deferred();

    var _path = function(fileName) { return path.join( rootDir, 'ssl', fileName) };

    fs.exists( _path( opt.clientFileName + '.crt') , function(ex) {

        if ( !ex ) throw 'createPKS12 can not find ' + opt.clientFileName + '.crt';
        _dfd_crt.resolve();

    });
    fs.exists( _path( opt.clientFileName + '.key') , function(ex) {

        if ( !ex ) throw 'createPKS12 can not find ' + opt.clientFileName + '.key';
        _dfd_key.resolve();
    });

    fs.exists( _path( opt.caFileName + '.crt') , function(ex) {

        if ( !ex ) throw 'createPKS12 can not find ' + opt.caFileName + '.crt';
        _dfd_ca_crt.resolve();
    });

    _.when( _dfd_crt, _dfd_key, _dfd_ca_crt ).done( function() {

        var params = [
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

        ];
        execOpenSSL(params, 'createPKS12').done( function() {
            _dfd_exit.resolve();
        }).fail( function(err) {
                _dfd_exit.reject(err);
            });
    });
    return _dfd_exit;
};

var getFingerprint = function() {

    var opt = !_.isEmpty(arguments) ? arguments[0] : options;
    opt.clientFileName = opt.clientFileName ? opt.clientFileName : options.clientFileName;

    var _dfd = _.Deferred();
    fs.exists( path.join( rootDir, 'ssl', opt.clientFileName + '.crt') , function(ex) {

        if ( !ex ) throw 'getFingerprint can not find ' + opt.clientFileName + '.crt';

        var params = [
            'x509',
            '-in',
            opt.clientFileName + '.crt',
            '-sha1',
            '-noout',
            '-fingerprint'

        ];
        execOpenSSL( params, 'getFingerprint' ).done( function() {
            _dfd.resolve();
        }).fail( function(err) {
                _dfd.reject(err);
            });
    });
    return _dfd;
};

var createClientSSL = function(opt) {

    options = opt;

    var   _dfd = _.Deferred();
    createClientKey(opt).done( function() {

        createCSR().done( function() {

            createClientCRT().done( function() {

                createPKS12().done( function() {

                    getFingerprint().done( function() {

                        getFingerprint().done( function() {

//                            TODO solve the issue with deferred resolve to send the result properly
                            _dfd.resolve( getFingerprint.fingerprint );
                        }).fail(function(err) {
                                _dfd.reject(err);
                            });
                    }).fail(function(err) {
                            _dfd.reject(err);
                        });
                }).fail(function(err) {
                        _dfd.reject(err);
                    });
            }).fail(function(err) {
                    _dfd.reject(err);
                });
        }).fail(function(err) {
                _dfd.reject(err);
            });
    }).fail( function(err) {
            _dfd.reject(err);
        });
    return _dfd;
};

exports.createClientKey      = createClientKey;
exports.createCSR            = createCSR;
exports.createClientCRT      = createClientCRT;
exports.createPKS12          = createPKS12;
exports.getFingerprint       = getFingerprint;
exports.createClientSSL      = createClientSSL;