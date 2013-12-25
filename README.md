openssl-p12
=

client's ssl certificate generator for Node. JS


### Install

  ```
  npm install openssl-p12
  ```
### Use

  ```js
  var p12 = require('openssl-p12').createClientSSL;
  var p12options = {
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

p12(p12options).done(function(options, sha1fingerprint) {
    console.log('SHA-1 fingerprint:', sha1fingerprint);
}).fail( function(err) {
    console.log(err);
});

  ```

### Description
This is an easy api client's ssl-certificate generator. openssl-p12 creates
client's ssl-certificate for HTTPS authentication and authorization. You'll need /ssl folder
in your project rootDir and ca.key, ca.crt (Certificate Authority) files to
sign up your client's certificates. The results of openssl-p12 are *.p12 (PKC12) file and SHA-1
fingerprint of client's certificate.


### HTTPS authorization example

```js
var fs = require('fs'),
    http = require('http'),
    https = require('https'),
    express = require('express');

var port = 443;

var httpsOptions = {
            key: './ssl/server.key',
            cert: './ssl/server.crt',
            ca: './ssl/ca.crt',
            requestCert: true,
            rejectUnauthorized: true,
            agent: false
        };

var app = express();

// SHA-1 fingerprint is openssl-p12 result that might be linked to exact user
var sha1fingerprint = 'CF:D4:95:58:04:9B:76:73:DC:EE:07:88:27:B0:48:1E:16:9D:F1:F9';

app.get('/', someHttpsMiddleWare, function (req, res) {

   if ( sha1fingerprint === req.connection.getPeerCertificate().fingerprint ) {
        res.send('Authorized User!');
   } else {
        res.send('Unauthorized User!')
   }
});
var server = https.createServer(options, app).listen(port, function(){
  console.log('Express server listening on port ' + port);
});
```
You will also need someHttpsMiddleWare (this one for example https://github.com/tgies/client-certificate-auth)

Now all visitors those how do not have ssl-certificate install into there browsers are rejected, all those how have certificates can visit your https
protected pages, but only that one how has certificate with exact SHA-1 fingerprint you remembered when create this
certificate might be allowed to page 'Authorized User!' So you can maintain your users' data base with SHA-1 fingerprints,
granting different HTTPS access.

### Options description

* `bitSize:` client key length (defaults to 2048)
* `clientFileName :` name of client's ssl-certificate file (defaults to 'client001')
* `C:` CSR country field (defaults to 'Example')
* `ST:` CSR state field (defaults to 'Example')
* `L:` CSR locality field (defaults to 'Example')
* `O:` CSR organization field (defaults to 'Example')
* `OU:` CSR organizational unit field (defaults to 'Example')
* `CN:` CSR common name field (defaults to 'Example')
* `emailAddress:` CSR email address field (defaults to 'example@example.ex')
* `clientPass:` Clients' password to encrypt PKS12 (.p12) file (defaults to q1w2e3r4t5y6)
* `caFileName:` CA files name (without extension), both files *.key and *.crt should exist (defaults to 'ca')
* `serial:` Client certificate serial number (defaults to '01')
* `days:` Client certificate valid period (defaults to 365)