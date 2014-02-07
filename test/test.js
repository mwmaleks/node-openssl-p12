/**
 * Created by mwmaleks on 21.12.13.
 */

var createClientSSL     = require('../lib/node-openssl-p12').createClientSSL;

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
    days: 365,
    publicKey: 'MIICQDCCASgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmBRkLLlYoSLHC9U3zCmoLvDxmIvYBX8PfXLYIcmzo0zKRf/HfOGJiALAfmqWHStLJTJ+igWAGE6H7ZLbpv6STbFOfPSf8lBZX8IsLufHyvh4LLX5sfm5Fpg30tsknlrG8B0eAJQXwuyyoXlRB58SSNHtEA13qkXUDB7GxZ53f76LuuqEngYHgsigRcW/7KBU41Qv0LiwhFf4mRsGnoATLJIP2lzMVzfksYLvfzSTirUlFu1p1TlEOaqqEi/YL2A7KHGhcOmlSEeDCQK+PsrrUFq3Pckw7vLgaWiFVBWf4hgxCus9iJXAcP7vR7zYxEqAXIVwwABpQu69KYt076w+LAgMBAAEWADANBgkqhkiG9w0BAQQFAAOCAQEAY8P4TRfCMDanooBuSgaZXV02Q38rnb27gm2NKHwf6iJ6qeb8k1hzHS0O3FEK82fmg1+EPtXswR3UQR87pYuJ3JeS/qiLYsPeGqPoNSmMZjqtnCqWRwl6OomkJLJoIa1oPuIViPDCM39C0JOVabyQNYMqL45dl47fLyPuiEPcJ7i9TeoT2CnCse645km1yRfE1vGB/BYK+rhlKcCUUpYHb/Nqcl+Ry3YiRv0q1hUjLWsEsYE6/dTLusqmsUPnRH586S4yWtJbO7xuGv0PgPNaUBlJIK8liEpbFrcCWwHyncRz6vY2hlpw6p5FdPM/HNeNOGpRUpGa4j6D72Lww9TPtw=='
};

createClientSSL(options).done(function(options, fingerprint) {

    console.log('-------------');
    console.log('Client\'s certificate created. SHA-1 fingerprint is:', fingerprint);
    console.log('createCRT:', options);
    console.log('-------------');

}).fail( function(err) {

    console.log('-------------');
    console.log('ERRORS: ', err);
});
