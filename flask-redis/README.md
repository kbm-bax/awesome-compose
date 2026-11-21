## Compose sample application
### Python/Flask application using a Redis database

Project structure:

```
.
├── Dockerfile
├── README.md
├── app.py
├── compose.yaml
└── requirements.txt
```

[_compose.yaml_](compose.yaml)

```
services:
   redis-auth:
     image: redislabs/redismod
     entrypoint: ['sh', '-c']
     command:
       - |
         ...
     volumes:
       - redis-auth:/run/redis-auth
   redis:
     image: redislabs/redismod
     command:
       - /run/redis-auth/redis.conf
       - --loadmodule
       ...
     volumes:
       - redis-auth:/run/redis-auth:ro
     depends_on:
       redis-auth:
         condition: service_completed_successfully
   web:
        build: .
        ports:
            - "8000:8000"
        environment:
            - REDIS_PASSWORD_FILE=/run/redis-auth/password
        volumes:
            - .:/code
            - redis-auth:/run/redis-auth:ro
        depends_on:
            ...
volumes:
   redis-auth:
```

Redis is not published on the host and requires a password. On first start, the one-shot `redis-auth` service generates a random password into the `redis-auth` volume; Redis loads it with `requirepass` and the web service reads it from `REDIS_PASSWORD_FILE`.

## Deploy with docker compose

```
$ docker compose up -d
[+] Running 24/24
 ⠿ redis Pulled   
 ...                                                                                                                                                                                                                                                                                                                                                                                                             
   ⠿ 565225d89260 Pull complete                                                                                                                                                                                                      
[+] Building 12.7s (10/10) FINISHED
 => [internal] load build definition from Dockerfile                                                                                                                                                                                  ...
[+] Running 3/3
 ⠿ Network flask-redis_default    Created                                                                                                                                                                                             
 ⠿ Container flask-redis-redis-1  Started                                                                                                                                                                                             
 ⠿ Container flask-redis-web-1    Started
```

## Expected result

Listing containers must show one container running and the port mapping as below:
```

$ docker compose ps
NAME                  COMMAND                  SERVICE             STATUS              PORTS
flask-redis-redis-1   "redis-server /run/r…"   redis               running             6379/tcp
flask-redis-web-1     "/bin/sh -c 'python …"   web                 running             0.0.0.0:8000->8000/tcp
```

After the application starts, navigate to `http://localhost:8000` in your web browser or run:
```
$ curl localhost:8000
This webpage has been viewed 2 time(s)
```

## Monitoring Redis keys

Connect to redis database by using ```redis-cli``` inside the redis container and monitor the keys.
```
$ docker compose exec redis sh -c 'REDISCLI_AUTH="$(cat /run/redis-auth/password)" redis-cli monitor'
OK
1646634062.732496 [0 172.21.0.3:33106] "INCRBY" "hits" "1"
1646634062.735669 [0 172.21.0.3:33106] "GET" "hits"
```


Stop and remove the containers
```
$ docker compose down
```
