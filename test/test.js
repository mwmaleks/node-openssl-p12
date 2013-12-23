/**
 * Created by mwmaleks on 21.12.13.
 */

var createClientSSL     = require('../lib/clients-ssl').createClientSSL;

var options = {
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
    days: 365
};

createClientSSL(options).done( function(fingerprint) {
    console.log('-------------');
    console.log('client\'s ', options.clientFileName, ' .key, .csr, .crt, .p12 created. SHA-1 fingerprint is:', fingerprint );
}).fail( function(err) {
    console.log('-------------');
    console.log('ERORS: ', err);
});
