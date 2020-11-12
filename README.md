# lets-encrypt

A library providing let's encrypt DNS providers for challenge resolution.

Currently provides powerDNS implementation, some new can be easily add 
thanks to go interfaces.

This project aims to automate renew certificates for the **Public** and **Private** WedSites, via [Let's Encrypt](https://letsencrypt.org/).
Obtaining a certificate for private sites is due to the fact that the program solve the DNS-01 challenge.
It will allow to prove that you control the DNS for your domain name by putting a specific value in a TXT record under that domain name.

After receiving the ACME client a token by Let's Encrypt, the TXT record will be created from that token, and the account key.

### Current Features
* Fully automated.
* Works well even if you have multiple web servers.
* Resolve ACME Lego Challenges.
  *  DNS (dns-01).
* Can talk to the Let's Encrypt CA.
* Create a Let's Encrypt account and save it.
* The private key is generated locally on your system.
* Free and Open Source Software, made with Go.


### System Requirements
```
"lets_encrypt_user": {
    "mail": "example@gmail.com",
    "account_path": "/etc/letsencrypt/account"
},
"dns_servers": [
    {
      "name": "Name",
      "type": "pdns",
      "url": "http://0.0.0.0:8080",
      "api_key": "Api Key",
      "server_id": "localhost"
    }
],
"certificates_root_path": "/etc/ssl-alert-renew/letsencrypt/certificates",
```