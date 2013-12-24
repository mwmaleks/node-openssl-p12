/**
 * Created by mwmaleks on 21.12.13.
 */

var createClientSSL     = require('../lib/clients-ssl').createClientSSL;

var options = {
    clientFileName :'client001'
//    C:'EX',
//    ST: 'Example',
//    L: 'Example',
//    O: 'Example',
//    OU: 'Example',
//    CN: 'Example',
//    emailAddress: 'example@example.ex',
//    clientPass: 'q1w2e3r4t5y6',
//    caFileName: 'ca',
//    serial: '01',
//    days: 365
};

createClientSSL(options).then( function( options, fingerprint ) {
    console.log('-------------');
    console.log('createCRT:', options );
    console.log('-------------');
    console.log(' *.key, *.csr, *.crt, *.p12 created. SHA-1 fingerprint is:', fingerprint );
} ,function(err) {
    console.log('-------------');
    console.log('ERORS: ', err);
});
