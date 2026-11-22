## Compose sample application
### Django application in dev mode

Project structure:
```
.
├── compose.yaml
├── app
    ├── Dockerfile
    ├── requirements.txt
    └── manage.py

```

[_compose.yaml_](compose.yaml)
```
services: 
  web: 
    build: app 
    ports: 
      - '8000:8000'
```

## Deploy with docker compose

```
$ docker compose up -d
Creating network "django_default" with the default driver
Building web
Step 1/6 : FROM python:3.7-alpine
...
...
Status: Downloaded newer image for python:3.7-alpine
Creating django_web_1 ... done

```

## Expected result

Listing containers must show one container running and the port mapping as below:
```
$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED              STATUS              PORTS                    NAMES
3adaea94142d        django_web          "python3 manage.py r…"   About a minute ago   Up About a minute   0.0.0.0:8000->8000/tcp   django_web_1
```

After the application starts, navigate to `http://localhost:8000` in your web browser:

Debug mode is off by default because Django's debug pages expose the
application's settings and server paths to anyone who can reach port 8000.
To turn it on for local development only, set `DEBUG=true` in the `web`
service's `environment` (or in a `.env` file next to `manage.py`). Set
`SECRET_KEY` the same way to keep sessions valid across restarts; otherwise a
random key is generated at startup. Set `ALLOWED_HOSTS` to a comma-separated
list when serving on a host name other than `localhost` or `127.0.0.1`.

Stop and remove the containers
```
$ docker compose down
```
