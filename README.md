# lets-encrypt

This project aims to automate renew certificates for the **Public** and **Private** 
WedSites, via [Let's Encrypt](https://letsencrypt.org/).  
Obtaining a certificate for private sites is due to the fact that the program solve the DNS-01 challenge.
It will allow to prove that you control the DNS for your domain name by putting a
specific value in a TXT record under that domain name. Then the DNS system will be queried 
by Let's Encrypt and if it finds a match, the certificate will be sent.


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
Used to create the Let's Encrypt account.  
After creation the user will be saved with the Public and Private Key and the registration file.
```
"lets_encrypt_user": {
    "mail": "example@gmail.com",
    "account_path": "/etc/letsencrypt/account"
}
```
Will be used to validate the challenge, by adding the TXT inside.  
```
"dns_servers": [
    {
      "name": "Name",
      "type": "pdns",
      "url": "http://0.0.0.0:8080",
      "api_key": "Api Key",
      "server_id": "localhost"
    }
]
```
Here to save the new certificate and key for the site.
```
"certificates_root_path": "/etc/ssl-alert-renew/letsencrypt/certificates",
```

### Usage

Those 3 methods are used to set up all we need to validate the challenge.  
Give them in argument, all the configuration already create in the `.json` file.
```
dnsServers := initDNSServers(config.DNSServers)
letsEncryptCustomUser, err := lets_encrypt.InitLetsEncryptUser(config.LetsEncryptUser)
letsEncrypt, err := lets_encrypt.InitLetsEncrypt(config.CertRootPath, letsEncryptCustomUser.GetLEUser())
```
Found the domain who is the owner of the site certificate that we want to renew.
```
dnsServers[...].IsAuthoritativeForDomain(siteURL)
```
Methods that communicate with Let's Encrypt to set the DNS Provider, and ask to resolve the challenge
to obtain the new certificate.
```
LetsEncrypt.SetDNSProvider(dns.DNSProvider{DNSServer: DNSServer})
LetsEncrypt.AskCertificate(siteURL)
```