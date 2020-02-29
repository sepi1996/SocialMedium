# SocialMedium

SocialMedium is a basic web application developed using the <a href="https://palletsprojects.com/p/flask/" target="_blank">**Flask**</a> framework where we can securely share 
our experiences or knowledge. This application was developed for the subject DAS, where we are aimed to deploy more a secure app rather than a full functionality one. For much more detailed information, please check out the attached documentation.

##### Table of Contents  
- [Features](#Features)
- [Requirements](#Requirements)
- [Installation](#Installation)
- [Deploy](#Deploy)


## Features

The basic features of this app are:
- User login and logout
- User registration and password reset via email
- Account customization
- CRUD operations on posts
- Private and public posts

Imagen


## Requirements

All the requirements will be covered in the installation section, but in this case I highly recomend using an
`Ubuntu 18.04 LTS` as a machine where all steps are checked


## Installation

- First of all, if we already have git installed we will clone this repository. Or we can just download and extract the ZIP file

- If not already installed we will need pip and python virtual environments (Is recommended follow this steps with a normal user rather than the root user)

```shell
$ sudo apt install python3-pip
$ sudo apt install python3-venv
```
- Inside the project directory, for simplicity, we will create our new virtual environment, we will activate it and install all the dependencies:
```shell
$ python3 -m venv mediumPepe/venv
$ source venv/bin/activate
$ pip3 install -r requeriments.txt
```
- Finally, we wil have to create a `config.json` for the secret key, and the credentials for the mail system. The following is an example of that text file
```JSON
{
        "SECRET_KEY": "theRandomSecretKeyGoesHere",
        "MAIL_USERNAME": "example@example.com",
        "MAIL_PASSWORD": "passwordExample"
}

```
- Now we are ready to launch or application. In the main directory (we can see run.py):
```shell
$ export FLASK_APP=run.py
$ flask run --host=0.0.0.0
```
We are ready to visit our web page at http://localhost:5000 
<imagen pagina sin nada aun>

## Deploy

We have seen how we can run the app, now we are going to deploy it on a <a href="https://www.nginx.com/" target="_blank">**Nginx**</a> server using <a href="https://gunicorn.org/" target="_blank">**Gunicorn**</a> 
- First we will install both components
```shell
$ sudo apt install nginx
$ pip3 install gunicorn
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

With this steps done, if we restart our nginx server `sudo systemctl restart nginx`, we just will be able to get the http://127.0.0.1:5000/static/main.css file 
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
directory=/home/pepe/mediumPepe
command=/home/pepe/venv/bin/gunicorn -w 3 run:app
user=pepe
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
As last recommendation if we are no able to acces to the aplication, we should check if our firewall is cutting the connection.
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
--Acabar con HTTPS


