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

function genPwd() {
    return Guid.create().value();
}

var Ssl = function() {

    var args = arguments ? arguments[0] : '';
    var opt = {
        ca_key  : ( args && args.ca_key )  ? args.ca_key  : 'ca.key',
        ca_crt : ( args && args.ca_crt )   ? args.ca_crt : 'ca.crt',
        ca_pwd  : ( args && args.ca_pwd )  ? args.ca_pwd  : 'ca.pwd',
        srv_key : ( args && args.srv_key ) ? args.srv_key : 'server.key',
        srv_crt : ( args && args.srv_crt ) ? args.srv_crt : 'server.crt',
        srv_pwd : ( args && args.srv_pwd ) ? args.srv_pwd : 'server.pwd'
    };
    var subj = ( args.country && args.state && args.city && args.company && args.division && args.domain && args.email ) ?
        '/C='            + args.country +
            '/ST='           + args.state +
            '/L='            + args.city +
            '/O='            + args.company +
            '/OU='           + args.division +
            '/CN='           + args.domain +
            '/emailAddress=' + args.email
        : '';

    if ( !subj ) throw '"subj" options are required';

    //    check if ssl folder exists
    ( !fs.existsSync( path.join(rootDir, 'ssl' ) ) ) && fs.mkdirSync( path.join( rootDir, 'ssl') );

    var   dfd_ca_key  = new _.Deferred()
        , dfd_ca_crt  = new _.Deferred()
        , dfd_srv_key = new _.Deferred()
        , dfd_srv_crt = new _.Deferred()
        , dfd_no_pass = new _.Deferred()
        , dfd_create_all = new _.Deferred();

    var _this = this;

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

        if ( ca_key && ca_crt && srv_key && srv_crt )  {

//          verify CA certificate
            verify.ca( opt.ca_crt ).done( function(valid_ca) {

//              if CA ok verify server certificate
                if ( valid_ca ) {
                    verify.srv( opt.ca_crt, opt.srv_crt ).done( function(valid_srv) {

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

// in case of there is no one file we create all
            dfd_create_all.resolve();

        } else {
//          some of the specified files not exist
            throw ' one or more specified files do not exist'
        }
        dfd_create_all.done( function() {
            
        }).fail();

    });
};