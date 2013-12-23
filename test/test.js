/**
 * Created by mwmaleks on 21.12.13.
 */

var   _                   = require('underscore')
    , createClientKey     = require('../lib/clients-ssl').createClientKey
    , createCSR           = require('../lib/clients-ssl').createCSR
    , createClientCRT     = require('../lib/clients-ssl').createClientCRT
    , createPKS12         = require('../lib/clients-ssl').createPKS12
    , getFingerprint      = require('../lib/clients-ssl').getFingerprint;


var options = {
    clientFileName :'client000',
    C:'RU',
    ST: 'Krasnodar',
    L: 'Krasnodar',
    O: 'PilotBook',
    OU: 'PilotBook',
    CN: 'Konstantin',
    emailAddress: 'admin@pilotbook.ru',
    clientPass: '1905',
    caFileName: 'ca',
    serial: '02',
    days: 365,
    bitSize: 2048
};

createClientKey(options).done( function() {

    console.log('createClientKey arguments = '.green, arguments);
    console.log('createClientKey: '.green, 'Done!'.yellow);

    createCSR(options).done( function() {
        console.log('createCSR arguments = '.green, arguments);

        console.log('createCSR: '.green, 'Done!'.yellow);

        createClientCRT(options).done( function() {
            console.log('createClientCRT arguments = '.green, arguments);

            console.log('createClientCRT: '.green, 'Done!'.yellow);

            createPKS12(options).done( function() {
                console.log('createPKS12 arguments = '.green, arguments);

                console.log('createPKS12: '.green, 'Done!'.yellow);

                getFingerprint(options).done( function() {
                    console.log('arguments = '.green, arguments);
                    console.log( getFingerprint.fingerprint, ' - Done!'.yellow );
                }).fail(function(err) {
                        console.log('error: '.red, err);
                });
            }).fail(function(err) {
                console.log('error: '.red, err);
            });
        }).fail(function(err) {
            console.log('error: '.red, err);
        });
    }).fail(function(err) {
            console.log('error: '.red, err);
    });
}).fail( function(err) {
   console.log('error: '.red, err);
});



