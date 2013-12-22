/**
 * Created by mwmaleks on 21.12.13.
 */

var   _ = require('underscore')
    , Ssl_cert = require('./ssl-cert.js').Ssl;

if ( _.isNull(Ssl_cert) )
    throw 'Class Position in not defined';

if ( !_.isFunction(Ssl_cert) )
    throw 'Varible Ssl is not Class (function constructor)';


var ssl_options = {
           country: 'RU',
           state: 'Krasnodar',
           city: 'Krasnosar',
           company: 'Pilotbook',
           division: 'Pilotbook',
           domain :'pilotbook.ru',
           email: 'admin@pilotbook.ru'
};


var ssl = new Ssl_cert( ssl_options).done( function(_ssl) {

    console.log('done!');

}).fail( function(err) {

    console.log('error: ', err);
});



