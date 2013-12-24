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

    options = getOptions.apply( this, arguments );

    if ( !fs.existsSync( dirPath ) )
        fs.mkdirSync( dirPath );

    if ( options.clientFileName == null ) {
        return getError('clientFileName not provided')
    }

    return createClientKey(options)
        .then( createCSR )
        .then( createClientCRT )
        .then( createPKS12 )
        .then( getFingerprint );
}

function getError(text) {
    return _.Deferred().reject(text);
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

function spawnOpenSSL( params, options) {

    var   openssl = spawn( 'openssl', params, {
            cwd: dirPath,
            env: process.env,
            customFds: [-1, -1, -1],
            setsid: false
          })
        , stdout = ''
        , stderr = ''
        , deferredSpawnOpenSSL = _.Deferred()
        , countExit = 1
        ;

    openssl.stdout.on('data', function (data) {
        stdout += (data || '').toString();
    });

    openssl.stderr.on('data', function (data) {
        stderr += (data || '').toString();
    });

    openssl.on('exit', function (code) {
        // при всех code != 0 это отваливается процесс на ошибке
        if (--countExit === 0 && code === 0)
            return;

        deferredSpawnOpenSSL.isRejected = true;
        deferredSpawnOpenSSL.reject(
            new Error('Invalid openssl exit code: ' + code + '\n% openssl ' + params.join(' ') + '\n' + stderr)
            , code
            , options
        );
    });

    openssl.on('close', function () {
        stdout = new Buffer( stdout, 'binary' ).toString('utf-8');
        stderr = new Buffer( stderr, 'binary' ).toString('utf-8');
        deferredSpawnOpenSSL.resolve(params, options, stdout, stderr);
    });

    return deferredSpawnOpenSSL;
}

function generateCSRSubject(options) {

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
}

function createClientKey(options) {

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
    return spawnOpenSSL( params , options );
}

function createCSR(options) {

    if (this.isRejected)
        return this;

    var opt = getOptions.apply( this, arguments )
        ;
    if ( !fs.existsSync( _path(opt.clientFileName + '.key')))
        throw 'there is no such keyFile :' + opt.clientFileName + '.key';

    return spawnOpenSSL( [
        'req',
        '-new',
        '-key',
        opt.clientFileName + '.key',
        '-subj',
        generateCSRSubject(opt),
        '-out',
        opt.clientFileName + '.csr'
    ], opt );
}

function createClientCRT(options) {

    if (this.isRejected)
        return this;

    var  opt = getOptions.apply( this, arguments)
        ,filesExist
        ;

    filesExist = fs.existsSync( _path(opt.caFileName + '.crt'))
        && fs.existsSync( _path(opt.caFileName + '.key'))
        && fs.existsSync( _path(opt.clientFileName + '.key'));

    if ( !filesExist )
        throw 'createClientCRT received wrong files';

    return spawnOpenSSL( [
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
}

function createPKS12(options) {

    if (this.isRejected)
        return this;

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

    return spawnOpenSSL([
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
}

function getFingerprint(options) {

    if (this.isRejected)
        return this;

    var opt = getOptions.apply( this, arguments );

    if ( !fs.existsSync( _path( opt.clientFileName + '.crt')) )
        throw 'file ' + opt.clientFileName + '.crt not found' ;

    return spawnOpenSSL( [
        'x509',
        '-in',
        opt.clientFileName + '.crt',
        '-sha1',
        '-noout',
        '-fingerprint'
    ], options );
}