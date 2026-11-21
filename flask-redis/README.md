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
  redis:
    image: redis:7.4
    networks:
      - backend
  web:
    build:
      context: .
      target: builder
    # flask requires SIGINT to stop gracefully
    # (default stop signal from Compose is SIGTERM)
    stop_signal: SIGINT
    ports:
      - '8000:8000'
    volumes:
      - .:/code
    networks:
      - frontend
      - backend
    depends_on:
      - redis
networks:
  frontend:
  backend:
    internal: true
```

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

Listing containers must show two containers running and the port mapping as below:
```

$ docker compose ps
NAME                  COMMAND                  SERVICE             STATUS              PORTS
flask-redis-redis-1   "docker-entrypoint.s…"   redis               running             6379/tcp
flask-redis-web-1     "/bin/sh -c 'python …"   web                 running             0.0.0.0:8000->8000/tcp
```

After the application starts, navigate to `http://localhost:8000` in your web browser or run:
```
$ curl localhost:8000
This webpage has been viewed 2 time(s)
```

## Monitoring Redis keys

Redis is only reachable on the internal `backend` network, so its port is not published on the host.
Run ```redis-cli``` inside the Redis container to monitor the keys.
```
$ docker compose exec redis redis-cli monitor
OK
1646634062.732496 [0 172.21.0.3:33106] "INCRBY" "hits" "1"
1646634062.735669 [0 172.21.0.3:33106] "GET" "hits"
```


Stop and remove the containers
```
$ docker compose down
```
