## Compose sample application

## Node.js application with Nginx proxy and Redis database

Project structure:
```
.
├── README.md
├── compose.yaml
├── nginx
│   ├── Dockerfile
│   └── nginx.conf
└── web
    ├── Dockerfile
    ├── package.json
    └── server.js

2 directories, 7 files


```
[_compose.yaml_](compose.yaml)
```
services:
  redis-auth:
    image: 'redislabs/redismod'
    entrypoint: ['sh', '-c']
    command:
      - |
        ...
    volumes:
      - redis-auth:/run/redis-auth
  redis:
    image: 'redislabs/redismod'
    command:
      - /run/redis-auth/redis.conf
      - --loadmodule
      ...
    volumes:
      - redis-auth:/run/redis-auth:ro
    depends_on:
      redis-auth:
        condition: service_completed_successfully
  web1:
    restart: on-failure
    build: ./web
    hostname: web1
    ports:
      - '81:5000'
    environment:
      - REDIS_PASSWORD_FILE=/run/redis-auth/password
    volumes:
      - redis-auth:/run/redis-auth:ro
    depends_on:
      redis-auth:
        condition: service_completed_successfully
  web2:
    ...
  nginx:
    build: ./nginx
    ports:
    - '80:80'
    depends_on:
    - web1
    - web2
volumes:
  redis-auth:
```
The compose file defines an application with four services `redis`, `nginx`, `web1` and `web2`, plus a one-shot `redis-auth` service.
When deploying the application, docker compose maps port 80 of the nginx service container to port 80 of the host as specified in the file.


> ℹ️ **_INFO_**  
> Redis is not published on the host and requires a password. On first start, `redis-auth` generates a random password into the `redis-auth` volume; Redis loads it with `requirepass` and the web services read it from `REDIS_PASSWORD_FILE`. To use `redis-cli`, run it inside the container:
> ```
> docker compose exec redis sh -c 'REDISCLI_AUTH="$(cat /run/redis-auth/password)" redis-cli'
> ```

## Deploy with docker compose

```
$ docker compose up -d
[+] Running 24/24
 ⠿ redis Pulled                                                                                                                                                                                                                      ...
   ⠿ 565225d89260 Pull complete                                                                                                                                                                                                      
[+] Building 2.4s (22/25)
 => [nginx-nodejs-redis_nginx internal] load build definition from Dockerfile                                                                                                                                                         ...
[+] Running 5/5
 ⠿ Network nginx-nodejs-redis_default    Created                                                                                                                                                                                      
 ⠿ Container nginx-nodejs-redis-web2-1   Started                                                                                                                                                                                      
 ⠿ Container nginx-nodejs-redis-redis-1  Started                                                                                                                                                                                      
 ⠿ Container nginx-nodejs-redis-web1-1   Started                                                                                                                                                                                      
 ⠿ Container nginx-nodejs-redis-nginx-1  Started
```


## Expected result

Listing containers must show three containers running and the port mapping as below:


```
docker-compose ps
```

## Testing the app

After the application starts, navigate to `http://localhost:80` in your web browser or run:

```
curl localhost:80
curl localhost:80
web1: Total number of visits is: 1
```

```
curl localhost:80
web1: Total number of visits is: 2
```
```
$ curl localhost:80
web2: Total number of visits is: 3
```



## Stop and remove the containers

```
$ docker compose down
```

