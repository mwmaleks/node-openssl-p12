/**
 * Created by mwmaleks on 21.12.13.
 */

var   spawn =   require('child_process').spawn
    , _ =       require('underscore')
    , fs =      require('fs')
//    , os =      require('os')
    , rootDir = process.cwd()
    , path =    require('path')
    , Guid = require('guid')
    , log = require('./lib/utils').log;

_.mixin( require('underscore.deferred') );

var verify = {
    ssl_command: [],

    ca : function( crt ) {

        var   _dfd = _.Deferred()
            ,openssl = spawn;
        var ca = spawn( 'openssl', ['verify', path.join( rootDir, 'ssl', crt ) ] );

        ca.on( 'exit', function() {
            ca.stdout.on( 'data', function(response) {

                ~response.indexOf('ОК') ? _dfd.resolve( true ) : _dfd.resolve( false );
            });
        });

        ca.stderr.on('data', function(err){
            log.error('verify ca');
            _dfd.reject(err);
        });
        return _dfd;
    },
    crt : function( ca_crt, crt) {

        var   _dfd = _.Deferred()
            ,openssl = spawn;
        var ca = spawn( 'openssl',
            [ 'verify','-CAfile', path.join( rootDir, 'ssl', ca_crt ), path.join( rootDir, 'ssl', crt ) ] );

        ca.on( 'exit', function() {
            ca.stdout.on( 'data', function(response) {

                ~response.indexOf('ОК') ? _dfd.resolve( true ) : _dfd.resolve( false );
            });
        });

        ca.stderr.on('data', function(err){
            log.error('verify crt');
            _dfd.reject(err);
        });
        return _dfd;
    }
};


var Ssl = function() {

    var args = arguments ? arguments[0] : '';
    var opt = {
        ca_key  : ( args && args.ca_key )  ? args.ca_key  : 'ca.key',
        ca_crt  : ( args && args.ca_crt )  ? args.ca_crt  : 'ca.crt',
        ca_pwd  : ( args && args.ca_pwd )  ? args.ca_pwd  : '',
        srv_key : ( args && args.srv_key ) ? args.srv_key : 'server.key',
        srv_crt : ( args && args.srv_crt ) ? args.srv_crt : 'server.crt',
        srv_pwd : ( args && args.srv_pwd ) ? args.srv_pwd : '',
        days    : ( args && args.days )    ? args.days    : 365
    };
    this.subj = ( args.country && args.state && args.city && args.company && args.division && args.domain && args.email ) ?
        '/C='            + args.country +
        '/ST='           + args.state +
        '/L='            + args.city +
        '/O='            + args.company +
        '/OU='           + args.division +
        '/CN='           + args.domain +
        '/emailAddress=' + args.email
        : '';

    if ( !this.subj ) throw '"subj" options are required';

    //    check if ssl folder exists
    ( !fs.existsSync( path.join(rootDir, 'ssl' ) ) ) && fs.mkdirSync( path.join( rootDir, 'ssl') );

    var   dfd_ca_key  = new _.Deferred()
        , dfd_ca_crt  = new _.Deferred()
        , dfd_srv_key = new _.Deferred()
        , dfd_srv_crt = new _.Deferred()
        , dfd_no_pass = new _.Deferred()
        , dfd_create_all = new _.Deferred()
        , dfd_complete_ssl = new _.Deferred();

    var _this = this;

//  check if certificates files exists
    fs.exists( path.join( rootDir, opt.ca_key ), function(ex) {
        dfd_ca_key.resolve(ex);
    });
    fs.exists( path.join( rootDir, opt.ca_crt ), function(ex) {
        dfd_ca_crt.resolve(ex);
    });
    fs.exists( path.join( rootDir, opt.srv_key ), function(ex) {
        dfd_srv_key.resolve(ex);
    });
    fs.exists( path.join( rootDir, opt.srv_crt ), function(ex) {
        dfd_srv_crt.resolve(ex);
    });
    _.when( dfd_ca_key, dfd_ca_crt, dfd_srv_key,dfd_srv_crt ).done( function( ca_key, ca_crt, srv_key, srv_crt ) {

//      in case all files exists verify them
        if ( ca_key && ca_crt && srv_key && srv_crt )  {

//          verify CA certificate
            verify.ca( opt.ca_crt ).done( function(valid_ca) {

//              if CA ok verify server certificate
                if ( valid_ca ) {
                    verify.crt( opt.ca_crt, opt.srv_crt ).done( function(valid_srv) {

//                  if server certificate is ok create no password certificate
                        if ( valid_srv ) {
                            dfd_no_pass.resolve();
                            return;
                        }
                        console.log('provided server certificate is invalid');
                        dfd_create_all.resolve();

                    }).fail( function(err) {
                            dfd_create_all.reject(err);
                    });
                    return;
                }
                console.log('provided CA is invalid');
                dfd_create_all.resolve();

            }).fail( function(err) {
                    dfd_create_all.reject(err);
            });

        } else if ( !( ca_key || ca_crt || srv_key || srv_crt ) ) {

//  in case of there is no one file we create all
            dfd_create_all.resolve();

        } else {
//          some of the specified files not exist
            throw ' one or more specified files do not exist'
        }
//      create certificates
        dfd_create_all.done( function() {

            var   dfd_ca    = _.Deferred()
                , dfd_server = _.Deferred();
            
//          send options to this
            _this.opt = opt;

//          this method creates ca.key, ca.csr request, and self-signed ca.crt
            _this.create_ca().done( function() {

                dfd_ca.resolve();
            }).fail( function(err) {

                dfd_ca.reject(err);
            });

//          this method creates server.key and server.csr request
            _this.create_key_req( opt.srv_key, opt.srv_pwd ).done( function( server_pwd_command ) {
                _this.srv_pwd_command = server_pwd_command;
                dfd_server.resolve();

            }).fail( function(err) {

                    dfd_server.reject(err);
            });

            _.when( dfd_ca, dfd_server ).done( function() {

//              this method signs server certificate by ca

                _this.sign_crt( opt.ca_key, opt.srv_key, '01' ).done( function() {

//                  in case of signing correct only no password server crt to create left
                    dfd_no_pass.resolve();
                }).fail( function(err) {

                    dfd_no_pass.reject(err);
                });

            }).fail( function(err) {
                dfd_no_pass.reject(err);
            });
        }).fail( function(err) {
            dfd_no_pass.reject(err);
        });
    });
    dfd_no_pass.done( function() {

        _this.create_noPass().done( function() {

            dfd_complete_ssl.resolve(_this);

        }).fail( function(err) {
            dfd_complete_ssl.reject(err);
        });
    }).fail( function(err) {
        dfd_complete_ssl.reject(err);
    });
    return dfd_complete_ssl;
};

function save_pwd( password, key) {

    var   dfd_pwd = _.Deferred()
        , pwd = [];

    var pwd_file = password ? path.join( rootDir, 'ssl', key.split( path.extname( key ) )[0] + '.txt') : false;

    if ( pwd_file ) {
        fs.writeFile( pwd_file, password, function(err) {

            if ( err ) {
                log.error('Error when saving password' );
                dfd_pwd.reject(err);
            }
            pwd.push(' -passout');
            pwd.push(' file: ' + key.split( path.extname( key ) )[0] + '.txt' );
            dfd_pwd.resolve(pwd);
        });
    } else {
        pwd.push(' -nodes');
        dfd_pwd.resolve(pwd);
    }
    return dfd_pwd;
}

function complete_ssl ( ssl_command, pwd, passphrase) {

    var _dfd = _.Deferred();

    ssl_command.push(pwd);
    ssl_command = _.flatten( ssl_command );
    console.log( 'openssl:'.blue,  ssl_command.join(' ') );
    var ca = spawn( 'openssl', ssl_command ,

        { cwd: path.join( rootDir, 'ssl'),
          env: process.env,
          customFds: [-1, -1, -1],
          setsid: false
    });
    ca.on( 'exit', function() {

        _dfd.resolve();
    });
    ca.stdout.on('data', function(data){
        console.log('stdout:'.red, data);
    });
    ca.stderr.on('data', function(err){
//        console.log('openssl err on command:'.red, ssl_command.join(' ') );
    });
    return _dfd;
}


//this method creates ca.key, ca.csr request, and self-signed ca.crt
Ssl.prototype.create_ca = function() {

    var   dfd_ca = _.Deferred()
        , _this = this;

    this.create_key_req( this.opt.ca_key, this.opt.ca_pwd ).done( function( pwd ) {
        _this.ca_pwd_command = pwd;
        dfd_ca.resolve();

    }).fail( function() {

        dfd_ca.reject();
    });
    return dfd_ca;
};

//this method creates .key and .csr request for any
Ssl.prototype.create_key_req = function( key, password ) {

    var   opt = this.opt
        , _this = this;

    var   dfd_key    = _.Deferred()
        , dfd_csr    = _.Deferred();

    var ssl_command = [
        'genrsa',
        '-des3',
        '-out',
        opt.ca_key,
        '2048' ];

    save_pwd( password, key ).done( function(pwd) {
        _this._pwd = pwd;
        complete_ssl( ssl_command, pwd, password).done( function() {

            dfd_key.resolve();

        }).fail( function(err) {
                dfd_key.reject(err);
            });
    });
    dfd_key.done( function() {
        console.log(rootDir, 'ssl', key );
        var ssl_command = [
            'req',
            '-new',
            '-key',
            path.join( rootDir, 'ssl', key ),
            '-subj',
            _this.subj,
            '-out',
            key.split( path.extname( key ) )[0] + '.csr'
        ];
        complete_ssl( ssl_command, _this._pwd, password ).done( function() {

            dfd_csr.resolve( _this._pwd );
        }).fail( function(err) {

                dfd_csr.reject(err);
            });

    }).fail( function(err) {

            dfd_csr.reject(err);
    });
    return dfd_csr;
};

Ssl.prototype.sign_crt = function( ca, crt, serial ) {

    var   dfd_sign = _.Deferred()
        , _this = this
        , opt = this.opt;

    var ssl_command = ca ?
        [
            'x509',
            '-req',
            '-days',
            opt.days,
            '-in',
            opt.ca_key.split( path.extname( opt.ca_key ) )[0] + '.csr',
            '-out',
            opt.ca_key.split( path.extname( opt.ca_key ) )[0] + '.crt' ,
            '-signkey',
            path.join( rootDir, 'ssl', opt.ca_key )
        ] :
        [
            'x509',
            '-req',
            '-days',
            opt.days,
            '-in',
            crt.split( path.extname( crt ) )[0] + '.csr',
            '-CA',
            opt.ca_crt,
            '-CAkey',
            opt.ca_key,
            '-set_serial',
            serial,
            '-out',
            crt.split( path.extname( crt ) )[0] + '.crt'
        ];

    complete_ssl( ssl_command, _this.ca_pwd_command, _this.opt.ca_pwd ).done( function() {

        dfd_sign.resolve();

    }).fail( function() {

        dfd_sign.reject();
    });
    return dfd_sign;
};

Ssl.prototype.create_noPass = function() {

    var   dfd_noPass = _.Deferred()
        , _this = this
        , opt = this.opt;

    var ssl_command = [
        'rsa',
        '-in',
        opt.srv_key,
        '-out',
        opt.srv_key.split( path.extname( opt.srv_key ) )[0] + '.nopass.key'
    ];

    complete_ssl( ssl_command, _this.srv_pwd_command, _this.opt.srv_pwd ).done( function() {

        dfd_noPass.resolve();

    }).fail( function() {

        dfd_noPass.reject();
    });

};

exports.Ssl = Ssl;