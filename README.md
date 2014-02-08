##node-openssl-p12

client's ssl certificate generator for Node JS based on OpenSSL 

### Synopsis

If your application requires the client's authentication 
by SSL ceritficate this would be great if the server 
generate and sign clint's certificates automatically and then send 
it back to client. node-openssl-p12 allows you to implement this in two ways.

### Description

The first one is to create `*.p12` file consisting with client's certificate, 
save its sha-1 fingerprint into the database and send it to the client by e-mail
for example (which is not good, actually). 

If you do not need to manage different access rights for your authorized users and you do 
not care about unauthorized users those may not understand why the connection was dropped, 
you just turn `rejectUnauthorized: true` in HTTPS settings (Express JS). 

If `rejectUnauthorized: false`, but `requestCert: true` (see example below), 
the server will not drop the connection and you have to manage authentication manually 
by SHA-1 fingerprint as well. This is possible by calling:

`req.connection.getPeerCertificate().fingerprint`

Before rendering the private page you just compare this fingerprint with those you saved as
result of node-openssl-p12 work.

The second way (most preferred) is about using `<keygen />` HTML5 tag (or google it for EE). 
`<keygen />` genereates a pair of private an public key. The public key is sent to the server with the form data 
which `<keygen />` tag was placed into. node-openssl-p12 use this key to create CPKAC, and certificate 
file that is should be sent back to the browser as response with the header 
`'Content-Type': 'application/x-x509-user-cert'`. This is the perfect way to free up users of knowledge how to install
ssl certificate into the browser. The fingerprint is also generated and saved for further usage. 

This second way implemented using both self signed CA and valid SLL signed by some third party CA.


### Install

  ```
  npm install node-openssl-p12
  ```
### Use the first way (PKC12)

NOTE: The current state it works only with self signed certificates.

Create `/ssl` folder in your project rootDir
and put `ca.key` , `ca.crt` (Certificate Authority) files, those 
are to sign your client certificates.


```js
  var p12 = require('node-openssl-p12').createClientSSL;
  var p12options = {
    bitSize: 2048,
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

Each certificate should be created with different `serial` and `clientFileName` 
or `clientFileName` files should be removed before the next `createClientSSL` call.

`*.p12` file saved in `ssl` folder. All done.


### Use the second way (<keygen /> and SPKAC)

Create `/ssl` folder in your project rootDir
and put `ca.key` , `ca.crt` (Certificate Authority) files, those 
are to sign your client certificates. If you use the certificate signed by some third party
use `server.key` and `server.crt`

Perform these commands in `ssl` folder.

```
$ mkdir db
$ mkdir db/certs
$ mkdir db/newcerts
$ touch db/index.txt
$ echo "02" > db/serial
```
It creates your certificates' database.

Then create `ca.config`
```
$ vim ca.config
```

and put this code inside:

```
[ ca ]
default_ca = CA_CLIENT

[ CA_CLIENT ]
dir = ./db
certs = $dir/certs
new_certs_dir = $dir/newcerts

database = $dir/index.txt
serial = $dir/serial
certificate = ./ca.crt
private_key = ./ca.key

default_days = 365
default_crl_days = 7
default_md = md5

policy = policy_anything

[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional
```

IMPORTANT:
`certificate` and `private_key` options should be specified with 
your `*.crt` and `*.key` files you use.


```js
  var p12 = require('node-openssl-p12').createClientSSL;
  var p12options = {
    clientFileName :'client001',
    C:'EX',
    ST: 'Example',
    L: 'Example',
    O: 'Example',
    OU: 'Example',
    CN: 'Example',
    emailAddress: 'example@example.ex',
    days: 365
    publicKey: req.body.public_key // a long string from <keygen /> tag
};

p12(p12options).done(function(options, sha1fingerprint) {

    console.log('SHA-1 fingerprint:', sha1fingerprint);
}).fail( function(err) {

    console.log(err);
});
```
NOTE: if you provide `publicKey` string `createClientSSL` works completely 
different way suitable only for `<ketgen />` case.


All done. Now just send the file back to the browser like this:

```js
fs.readFile( path.join( rootDir, 'ssl', 'client001'), function(err, data) {

        if (err) {
           console.error('error while open client ssl file:', err);
           return;
        }
        res.set('Last-Modified', (new Date).setHours(-24));
        res.set('Accept-Ranges', 'bytes');
        res.set('Content-Length', data.length);
        res.set('Content-Type', 'application/x-x509-user-cert');
        res.send(data);
    });
```
NOTE:
If you discover an error after then second certificate generation
open `/ssl/db/index.txt.attr` and switch `unique_subject = no`


### Options description

* `bitSize:` client key length (defaults to 2048)
* `clientFileName :` name of the client's ssl-certificate file (defaults to 'client001')
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
* `publicKey:` public key - `req.body.public_key` from `<keygen name= "public_key"/>`

### HTTPS authentication example

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
            rejectUnauthorized: false,// using rejectUnauthorized: true - drops 
                                      // connection if user has not certificate
            agent: false
        };

var app = express();

/* express options are avoided */

// SHA-1 fingerprint is node-openssl-p12 result that might be linked to exact user
var sha1fingerprint = 'CF:D4:95:58:04:9B:76:73:DC:EE:07:88:27:B0:48:1E:16:9D:F1:F9';

app.get('/', someHttpsMiddleWare, function (req, res) {

   if ( sha1fingerprint === req.connection.getPeerCertificate().fingerprint ) {
        res.send('Authorized User!');
   } else {
        res.send('Unauthorized User!');
   }
});
var server = https.createServer( httpsOptions, app ).listen(port, function() {
  console.log('Express server listening on port ' + port);
});
```
You will also need someHttpsMiddleWare (this one for example https://github.com/tgies/client-certificate-auth)

Now all visitors those having not ssl-certificate installed into there browsers are 
redirected or rejected, all those how have certificates can visit your https protected 
pages, but only that one how has the certificate with exact SHA-1 fingerprint you remembered 
when created this certificate might be allowed to page 'Authorized User!' So you can maintain 
your users' data base with SHA-1 fingerprints, granting different HTTPS access rights.
