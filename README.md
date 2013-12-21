ssl-cert
===

#### self-signed ssl certificate generator for Node. JS

### Install

  ```
  npm install ssl-cert
  ```
### Use

  ```js
  var ssl = reqire('ssl-cert');
  var ssl_options = {
  
  };

  ```

### Description

This library is written for the purpose to create self-signed ssl 
certificates directly from Node. JS project, providing some simple 
options. It allows to create a CA, server and client ssl - certificates 
signed by your CA (both generated using this library or your own one) 
for use them further ssl client authentication and authorization by sha-1 
fingerprint.

### API
