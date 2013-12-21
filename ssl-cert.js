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
        ca_cert : ( args && args.ca_cert ) ? args.ca_cert : 'ca.crt',
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
};