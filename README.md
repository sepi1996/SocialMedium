# SocialMedium

SocialMedium is a basic web application developed using the <a href="https://palletsprojects.com/p/flask/" target="_blank">**Flask**</a> framework where we can securely share 
our experiences or knowledge. This application was developed for the subject DAS, where we are aimed to deploy more a secure app rather than a full functionality one. For much more detailed information, please check out the attached documentation.

##### Table of Contents  
- [Features](#Features)
- [Security](#Security)
- [Requirements](#Requirements)
- [Installation](#Installation)
- [Deploy](#Deploy)


## Features

The basic features of this app are:
- User login and logout
- User registration
- Account customization
- CRUD operations on posts
- Personal, private and public posts

## Security
The basic security features of this app are:
- Use of HTTPS for secure connections
- Secure password storage using PBKDF functions
- Personal posts, are stored in the DB encrypted, using different keys for each user
- Trusted devices for a more secure log in
- 2FA
- Account activation via e-mail
- Secure password recovery via e-mail and personal cuestions
- Recaptcha protection
- Post sharing via JSON Web Signature(JWS)
- Different views and options depending on the post type
- Validated user inputs
- Logging of events
![alt text](https://user-images.githubusercontent.com/18005114/76704245-272ce480-66c7-11ea-8498-7851a20faa0a.png)
## Requirements

All the requirements will be covered in the installation section, but in this case I highly recomend using an
`Ubuntu 18.04 LTS` as a machine where all steps are checked


## Installation

- First of all, if we already have git installed we will clone this repository. Or we can just download and extract the ZIP file.

```shell
$ git clone https://github.com/sepi1996/SocialMedium.git
```

- If not already installed we will need pip and python virtual environments (Is recommended follow this steps with a normal user rather than the root user)

```shell
#User creation
$ adduser socialMediumUser
$ adduser socialMediumUser sudo
$ su socialMediumUser

$ sudo apt install python3-pip
$ sudo apt install python3-venv
```
- Inside the project directory, for simplicity, we will create our new virtual environment, we will activate it and install all the dependencies:
```shell
$ cd SocialMedium
$ python3 -m venv ./venv
$ source venv/bin/activate
$ pip install -r requeriments.txt
```
- Finally, we wil have to create a `config.json` in the `/etc` directory, for the secret key, and the credentials for the mail system. The following is an example of that text file
```JSON
{
        "SECRET_KEY": "theRandomSecretKeyGoesHere",
        "MAIL_USERNAME": "example@example.com",
        "MAIL_PASSWORD": "passwordExample",
        "RECAPTCHA_PUBLIC_KEY": "secretPublicKey",
        "RECAPTCHA_PRIVATE_KEY": "secretPrivateKey"
}

```
- Now we are ready to launch or application. In the main directory (we can see run.py):
```shell
$ export FLASK_APP=run.py
$ flask run --host=0.0.0.0
```
We are ready to visit our web page at http://localhost:5000 

![alt text](https://user-images.githubusercontent.com/18005114/76700138-0acb8080-66a4-11ea-8868-402b9c44af05.png)

## Deploy

We have seen how we can run the app, now we are going to deploy it on a <a href="https://www.nginx.com/" target="_blank">**Nginx**</a> server using <a href="https://gunicorn.org/" target="_blank">**Gunicorn**</a> 
- First we will install both components
```shell
$ sudo apt install nginx
$ pip install gunicorn
```
- Now we remove the default Nginx site and we will create our new web site:
```shell
$ sudo rm /etc/nginx/sites-enabled/default
$ sudo touch /etc/nginx/sites-enabled/socialMedium
```
And paste the following content, accorder to your context:
```TXT
server{
        server_port 80;
        server_name "Our public IP address or domain name";

        location /static {
                alias /home/pepe/mediumPepe/medium/static;
        }

        location / {
                proxy_pass http://localhost:8000;
                include /etc/nginx/proxy_params;
                proxy_redirect off;
        }
}
```

With this steps done, if we restart our nginx server `sudo systemctl restart nginx`, we just will be able to get the http://127.0.0.1:80/static/main.css file 
because Gunicorn is not running.

So finally, we will run Gunicorn as follow:
```shell
$ gunicorn -w 3 run:app
```
Note that 3, is the number of coworkers that Gunicorn will be using. This number should be the number of cores per 2 plus 1. (We can find out the
number of procs using the `nproc` command.

Additionally, if we want Gunicorn to run in the background, we can use supervisor as follows:
- First, let's install it.
```shell
$ sudo apt install supervisor
```
- Create the config file, here is an example of my `/etc/supervisor/conf.d/socialMedium.conf` file:
```TXT
[program:socialMedium]
directory=/home/socialMediumUser/SocialMedium
command=/home/socialMediumUser/SocailMedium/venv/bin/gunicorn -w 3 run:app
user=socialMediumUser
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true

stderr_logfile=/var/log/socialMedium/socialMedium.err.log
stdout_logfile=/var/log/socialMedium/socialMedium.out.log
```

- Now we are going to create the log files:
```shell
$ sudo mkdir -p /var/log/socialMedium/
$ sudo tocuh /var/log/socialMedium/socialMedium.out.log
$ sudo touch /var/log/socialMedium/socialMedium.err.log

```
- One additional step is to change the default file size upload in Nging to 5M for our profile pictures. Even our server resizes the 
pictures for space optimizaion, if this file is to large it can not be upload. For so in `/etc/nginx/nginx.conf`:

> client_max_body_size 5M;

- Finally we restart Nginx and the supervisor and our web site will be in production!
```shell
$ sudo supervisorctl reload
$ sudo systemctl restart nginx

```
As last recommendation if we are no able to acces to the aplication, we should check if our firewall is blocking the connection.
- If Uncomplicated Firewall (ufw) is active, we can allow the conexions with:
```shell
$ sudo nano ufw allow http/tcp
```
- Or if we are using Iptables
```shell
#For stateless
$ iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT

#For stateful
$ sudo iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
```
- And check if the services are runing with:
```shell
$ ps aux | grep nginx
$ ps aux | grep gunicorn
$ ps aux | grep supervisord
```

- And listening on the correct ports with:
```shell
$ netstat -anpt
```

![alt text](https://user-images.githubusercontent.com/18005114/76700233-22efcf80-66a5-11ea-81df-718f47151185.png)
- Finally, we will use HTTPS instead of HTTP, for obvious reasons. For so, we will use <a href="https://certbot.eff.org/" target="_blank">**Certbot**</a>. There you can find the exact commands you need to set up your HTTPS server. Anyway, I will left here the commands needed to install it on a `Ubuntu 18.04 LTS` with a `Nginx`
```shell
$ sudo apt-get update
$ sudo apt-get install software-properties-common
$ sudo add-apt-repository universe
$ sudo add-apt-repository ppa:certbot/certbot
$ sudo apt-get update
$ sudo apt-get install certbot python-certbot-nginx
$ sudo certbot certonly --nginx
$ sudo certbot renew --dry-run

```
As a good practice, we will choose during the configuration the option, that redirects all traffic to port 443(remember to allow this port in the firewalls rules), and we will create a cron job, so we don't have to renew manually the certificate. For so, we will add the following line in the crontab file:
```shell
11 1 1 * * sudo certbot renew --quiet
```
![alt text](https://user-images.githubusercontent.com/18005114/76702094-8b937800-66b6-11ea-9430-aed88971faa8.png)

