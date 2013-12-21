/**
 * Created by mwmaleks on 21.12.13.
 */

var   spawn =   require('child_process').spawn
    , _ =       require('underscore')
    , fs =      require('fs')
//    , os =      require('os')
    , rootDir = process.cwd()
    , path =    require('path')
    , Guid = require('guid');

_.mixin( require('underscore.deferred') );

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
        , dfd_complete_ssl = new Deferred();

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

            var dfd_sign_server_crt = _.Deferred();
            
//          send options to this
            _this.opt = opt;

//          this method creates ca.key, ca.csr request, and self-signed ca.crt
            _this.create_ca().done( function() {

                dfd_sign_server_crt.resolve();
            }).fail( function(err) {

                dfd_sign_server_crt.reject(err);
            });

//          this method creates server.key and server.csr request
            _this.create_key_req().done( function() {

                dfd_sign_server_crt.resolve();

            }).fail( function(err) {

                dfd_sign_server_crt.reject(err);
            });

            dfd_sign_server_crt.done( function() {

//              this method signs server certificate by ca
                _this.sign_crt().done( function() {

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

            dfd_complete_ssl.resolve();

        }).fail( function(err) {
            dfd_complete_ssl.reject(err);
        });
    }).fail( function(err) {
        dfd_complete_ssl.reject(err);
    });
    return dfd_complete_ssl;
};



Ssl.prototype.create_ca = function() {
    
    var opt = this.opt;

    var   dfd_pwd       = _.Deferred()
        , dfd_ca_key    = _.Deferred()
        , dfd_ca_csr    = _.Deferred()
        , dfd_ca_sign   = _.Deferred()
        , _this = this;

    function complete_ssl (ssl_command) {

        var _dfd = _.Deferred();

        _.flatten( ssl_command.push(pwd) );
        var ca_csr = spawn( 'openssl', ssl_command );

        ca_csr.on( 'exit', function() {

            _dfd.resolve();
        });

        ca_csr.stderr.on('data', function(err){

            _dfd.reject(err);
        });
        return _dfd;
    }

    var ssl_command = [
        'genrsa',
        '--des3','-out',
        path.join( rootDir, 'ssl', opt.ca_key),
        2048 ],
        pwd = [];

    var pwd_file = opt.ca_pwd ? path.join( rootDir, 'ssl/ca_pwd.txt') : false;

    if ( pwd_file ) {
        fs.writeFile( pwd_file, opt.ca_pwd, function(err) {

            if ( err ) {
                console.log( 'Error when saving password to temp file' );
                throw err;
            }
            pwd.push('-passout');
            pwd.push('file:' + pwd_file );
            dfd_pwd.resolve();
        });
    } else {
        pwd.push('-nodes');
        dfd_pwd.resolve();
    }
    dfd_pwd.done( function() {
        complete_ssl( function() {

            dfd_ca_key.resolve();

        }).done.fiail( function(err) {
                dfd_ca_key.reject(err);
        });
    });
    dfd_ca_key.done( function() {

        var ssl_command = [
            'req',
            '-new','-key',
            path.join( rootDir, 'ssl', opt.ca_key), '-subj',
            _this.subj, '-out',
            path.join( rootDir, 'ssl', opt.ca_key.splice( path.extname( opt.ca_key ) )[0] + '.csr')
        ];
        complete_ssl(ssl_command).done( function() {

            dfd_ca_csr.resolve();
        }).fail( function(err) {

            dfd_ca_csr.reject(err);
        });

    }).fail( function(err) {

            dfd_ca_csr.reject(err);
    });
    dfd_ca_csr.done( function() {

        var ssl_command = [
            'x509',
            '-req','-days',
            opt.days, '-in',
            path.join( rootDir, 'ssl', opt.ca_key.splice( path.extname( opt.ca_key ) )[0] + '.csr' ), '-out',
            path.join( rootDir, 'ssl', opt.ca_key.splice( path.extname( opt.ca_key ) )[0] + '.crt' ), '-signkey',
            path.join( rootDir, 'ssl', opt.ca_key )
        ];

        complete_ssl(ssl_command).done( function() {

            dfd_ca_sign.resolve();

        }).fail( function() {

            dfd_ca_sign.reject();
        });
    }).fail(function() {

        dfd_ca_sign.reject();
    });
    return dfd_ca_sign;
};

Ssl.prototype.create_key_req = function() {};

Ssl.prototype.sign_crt = function() {};

Ssl.prototype.create_noPass = function() {};
