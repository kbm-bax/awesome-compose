## Plex
This example provides a base setup for using [Plex](https://www.plex.tv/).
More details on how to customize the installation and the compose file can be found in [linuxserver documentation](https://github.com/linuxserver/docker-plex).
Alternatively, you can use different plex images (e.g. official plex image by [plexinc](https://github.com/plexinc/pms-docker))


Project structure:
```
.
├── .env
├── compose.yaml
└── README.md
```

[_compose.yaml_](compose.yaml)
``` yaml
services:
  plex:
    image: linuxserver/plex
    ports:
      - ${PLEX_BIND_ADDRESS:-127.0.0.1}:32400:32400
    environment:
      - PLEX_CLAIM=${PLEX_CLAIM:?...}
```

## Configuration

### .env
Before deploying this setup, you need to configure the following values in the [.env](.env) file.
- PLEX_MEDIA_PATH
- PLEX_CLAIM: a claim token from https://www.plex.tv/claim. The token is valid for 4 minutes, so get a fresh one right before the first `docker compose up`, and do not commit it. On the first start the container uses it to claim the server for your Plex account before Plex starts serving requests. The claim is stored in the `plex-config` volume, so later starts do not need a valid token.

An unclaimed Plex server lets any client on its subnet run the setup wizard and claim it. For that reason, port 32400 is only published on `127.0.0.1` by default, and the sample does not use host networking. Check that the first start logs `Server claimed successfully` (`docker compose logs plex`). If the claim fails, claim the server from the Docker host itself (http://localhost:32400/web, or through an SSH tunnel such as `ssh -L 32400:localhost:32400 <docker-host>`).

Once the server is claimed, you can make it reachable from other devices by setting `PLEX_BIND_ADDRESS` (for example `PLEX_BIND_ADDRESS=0.0.0.0`) in the [.env](.env) file and running `docker compose up -d` again.

### Hardware Acceleration
Check out the description for Hardware Acceleration support in the [documentation](https://github.com/linuxserver/docker-plex).

## Deploy with docker compose
When deploying this setup, the web interface will be available on port 32400 of the Docker host (e.g. http://localhost:32400/web).

``` shell
$ docker compose up -d
Starting plex ... done
```


## Expected result

Check containers are running:
```
$ docker ps
CONTAINER ID   IMAGE                             COMMAND                  CREATED          STATUS         PORTS                                          NAMES
62fc3ff1f1a0   linuxserver/plex                  "/init"                  38 seconds ago   Up 3 seconds   127.0.0.1:32400->32400/tcp, 1900/udp, ...      plex
```

Navigate to `http://localhost:32400/web` in your web browser to access the plex web interface.


Stop the containers with
``` shell
$ docker compose down
# To delete all data run:
$ docker compose down -v
```
