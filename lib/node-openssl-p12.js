/**
 * Created by mwmaleks on 23.12.13.
 */

// TODO replace all of the throws with deferred reject

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
 * @param {String} [options.OU] CSR organizational unit field (no defaults')
 * @param {String} [options.CN] CSR common name field (defaults to 'Example')
 * @param {String} [options.emailAddress] CSR email address field (defaults to 'example@example.ex')
 * @param {String} [options.clientPass] Clients' password to encrypt PKS12 (.p12) file (defaults to q1w2e3r4t5y6)
 * @param {String} [options.caFileName] CA files name (without extension), both files *.key and *.crt should exist (defaults to 'ca')
 * @param {String} [options.serial] Client certificate serial number (defaults to '01')
 * @param {Number} [options.days] Client certificate valid period (defaults to 365)
 * @param {String} [options.publicKey] Public key received from <keygen /> tag
 * @api public
 */
function createClientSSL(options) {

    options = getOptions.apply( this, arguments );

    if ( !fs.existsSync( dirPath ) )
        fs.mkdirSync( dirPath );

    if ( options.clientFileName == null ) {
        return _getError('clientFileName not provided');
    }

    if ( options.publicKey ) {

        return genSpkac(options)
            .then( signSpkac )
            .then( dgstSha1)
            .then( function(options, stdout, stderr) {

                if (this.isRejected)
                    return this;
                var   deferred = _.Deferred()
                    , _fingerprint
                    , _fgpArr = [];

                if ( stdout.indexOf('SHA1('+ options.clientFileName +')= ') !== -1 ) {

                    _fingerprint = stdout.replace('SHA1('+ options.clientFileName +')= ', '');

                    for( var i = 0; i <= _fingerprint.length - 2; i +=2 ) {

                        _fgpArr.push( _fingerprint[i] + _fingerprint[ i+1 ] );
                    }
                    deferred.resolve(options, _fgpArr.join(':'));

                    fs.unlinkSync(_path(options.clientFileName + '.spkac'));

                    return deferred;
                }
                deferred.reject( new Error ('No fingerprint'));
                return deferred;
            });

    }
    return createClientKey(options)
        .then( createCSR )
        .then( createClientCRT )
        .then( createPKS12 )
        .then( getFingerprint )
        .then(function(options, stdout, stderr) {

            if (this.isRejected)
                return this;

            fs.unlinkSync(_path(options.clientFileName + '.key'));
            fs.unlinkSync(_path(options.clientFileName + '.csr'));
            fs.unlinkSync(_path(options.clientFileName + '.crt'));

            var   deferred = _.Deferred()
                , _fingerprint = stdout.match(/Fingerprint=([0-9a-fA-F:]+)$/m);

            _fingerprint
                ? deferred.resolve(options, _fingerprint[1])
                : deferred.reject( new Error ('No fingerprint'));

            return deferred;
        });
}
/**
 *  creates new Deferred object rejected with new Error object of errText
 * @param errText - error text
 * @returns {*}
 * * @private
 */
function _getError(errText) {

    var deferred = _.Deferred();

    deferred.reject( new Error( errText ));
    deferred.isRejected = true;
    return deferred;
}
/**
 * returns dirPath joined with fileName
 * @param fileName file name
 * @returns {*}
 * @private
 */
function _path(fileName) {

    return path.join( dirPath, fileName );
}
/**
 * check is obj types to 'Object'
 * @param obj
 * @returns {boolean}
 */
function isObject(obj) {

    return Object.prototype.toString.call(obj) === '[object Object]';
}

/**
 * check is bool types to 'Boolean'
 * @param bool
 * @returns {boolean}
 */
function isBool(bool) {

    return Object.prototype.toString.call(bool) === '[object Boolean]';
}
/**
 * tags provided options with default ones
 * @param options
 * @returns {}
 */
function getOptions(options) {

    var defaultOptions = {
        bitSize: 2048,
        clientFileName :'client001',
        C:'EX',
        ST: 'Example',
        L: 'Example',
        O: 'Example',
        CN: 'Example',
        emailAddress: 'example@example.ex',
        clientPass: 'q1w2e3r4t5y6',
        caFileName: 'ca',
        serial: '01',
        days: 365,
        publicKey: null
    };

    options = isObject(options) ? options : {};

    for ( var param in defaultOptions ) {
        if (defaultOptions.hasOwnProperty(param))
            options[param] = options[param] != null ? options[param] : defaultOptions[param];
    }

    return options;
}
/**
 * perform openssl commands in child process
 * @param params
 * @param options
 * @returns {*}
 */
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
        deferredSpawnOpenSSL.resolve(options, stdout, stderr);
    });

    return deferredSpawnOpenSSL;
}
/**
 * generates CSR subject
 * @param options
 * @returns {string}
 */
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
/**
 * creates client certificate using passed options
 * @param options
 * @returns {*}
 */
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
        return _getError( options.clientFileName + ' already exists' );

    params.push('-out', options.clientFileName + '.key', options.bitSize);

//      create key
    return spawnOpenSSL( params , options );
}
/**
 * creates CSR file
 * @param options
 * @returns {*}
 */
function createCSR(options) {

    if (this.isRejected)
        return this;

    var opt = getOptions.apply( this, arguments )
        ;
    if ( !fs.existsSync( _path(opt.clientFileName + '.key')))
        return _getError( 'there is no such keyFile :' + opt.clientFileName + '.key' );

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
/**
 * create client's certificate file (*.crt)
 * @param options
 * @returns {*}
 */
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
        return _getError( 'createClientCRT received wrong files' );

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
/**
 * creates *.p12 file
 * @param options
 * @returns {*}
 */
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
        return _getError( 'some of ' + opt.clientFileName + '.crt or '
            + opt.clientFileName + '.key or '
            + opt.caFileName + '.crt not found' );

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

    ], options);
}
/**
 * gets *.p12 fingerprint
 * @param options
 * @returns {*}
 */
function getFingerprint(options) {

    if (this.isRejected)
        return this;

    var opt = getOptions.apply( this, arguments );

    if ( !fs.existsSync( _path( opt.clientFileName + '.crt')) )
        return _getError( 'file ' + opt.clientFileName + '.crt not found');

    return spawnOpenSSL( [
        'x509',
        '-in',
        opt.clientFileName + '.crt',
        '-sha1',
        '-noout',
        '-fingerprint'
    ], options );
}
/**
 * perform 'openssl dgst -sha1 filename' command to get fingerprint different
 * to 'getFingerprint' way
 * @param options
 * @returns {*}
 */
function dgstSha1(options) {

    if (this.isRejected)
        return this;

    var opt = getOptions.apply( this, arguments );

    if ( !fs.existsSync( _path( opt.clientFileName )) )
        return _getError( 'file ' + opt.clientFileName + ' not found' );

    return spawnOpenSSL( [
        'dgst',
        '-sha1',
        opt.clientFileName,
    ], options );
}
/**
 * creates SPKAC file
 * @param options
 * @returns {*}
 */
function genSpkac(options) {

    var   genSpkacDeferred = _.Deferred()
        , spkac
        ;

    if (this.isRejected)
        return this;

    var opt = getOptions.apply( this, arguments );

    if ( fs.existsSync( _path( opt.clientFileName + '.spkac')) )
        return _getError( 'file ' + opt.clientFileName + '.spkac already exists' );

    spkac = [ 'SPKAC =' + opt.publicKey.replace(/[\t\n\r\0]/g, ''),
        'CN=' + opt.CN,
        'emailAddress=' + opt.emailAddress ];

    opt.OU && spkac.push('OU=' + opt.OU);
    opt.O && spkac.push( 'organizationName=' + opt.O);
    spkac.push('countryName=' + opt.C);
    opt.ST && spkac.push('stateOrProvinceName=' + opt.ST);
    spkac.push('localityName=' + opt.L);

    fs.writeFile( path.join( dirPath, opt.clientFileName + '.spkac' ), spkac.join('\n'), function(err) {

        if (err) {
            console.log('error from write spkac file = ', err);
            genSpkacDeferred.reject(err);
            genSpkacDeferred.isRejected = true;

        }
        genSpkacDeferred.resolve(options);
    });
    return genSpkacDeferred;
}
/**
 * create signed certificate file
 * @param options
 * @returns {*}
 */
function signSpkac(options) {

    if (this.isRejected)
        return this;

    var opt = getOptions.apply( this, arguments );

    if ( !fs.existsSync( _path( opt.clientFileName + '.spkac')) )
        return _getError( 'file ' + opt.clientFileName + '.spkalid openssl exound' );

    return spawnOpenSSL( [
        'ca',
        '-config',
        'ca.config',
        '-days',
        opt.days,
        '-batch',
        '-spkac',
        opt.clientFileName + '.spkac',
        '-out',
        opt.clientFileName
    ], options );
}