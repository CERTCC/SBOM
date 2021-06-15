# Install 

SwiftBOM can be installed on a private server.  If you try to open the HTML files directly, browser may not render the content properly and block access to 
scripts. Any webserver such as Apache, Nginx, tinyhttpd can host SBOM static files for you to use it on 
a private server such as a server accessible only to an internal LAN

* Clone this git repo in a local folder such as /var/www/SBOM/  
`git clone https://github.com/CERTCC/SBOM/`

* Create the following custom configuration to map this folder to a http url path 
``` 
#Nginx  
    location ^~ /sbom/ {  
       root         /var/www/SBOM/SwiftBOM/;  
   }  
  ```

 ```
 #Apache
 Alias /sbom/ "/var/www/SBOM/sbom-demo/"
 <Directory "/var/www/SBOM/sbom-demo/">
   Options Indexes FollowSymLinks
   AllowOverride None
   Required all granted
 </Directory> 
 ```
 

* Reload or Restart your webserver and visit your server's URL http://hostname/sbom/
