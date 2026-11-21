## Compose sample
### Prometheus & Grafana

Project structure:
```
.
├── compose.yaml
├── grafana
│   └── datasource.yml
├── prometheus
│   └── prometheus.yml
└── README.md
```

[_compose.yaml_](compose.yaml)
```
services:
  prometheus:
    image: prom/prometheus
    ...
    ports:
      - 9090:9090
  grafana:
    image: grafana/grafana
    ...
    ports:
      - 127.0.0.1:3000:3000
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
```
The compose file defines a stack with two services `prometheus` and `grafana`.
When deploying the stack, docker compose maps port the default ports for each service to the equivalent ports on the host in order to inspect easier the web interface of each service.
Make sure the ports 9090 and 3000 on the host are not already in use.
Grafana is only published on the host's loopback interface (`127.0.0.1`).

## Deploy with docker compose

Grafana's `admin` password is not stored in the compose file. Choose your own
password and provide it through the `GRAFANA_ADMIN_PASSWORD` environment
variable, either exported in your shell or in a `.env` file next to
`compose.yaml` (which is ignored by git). Grafana refuses to start if it is not set.

```
$ echo "GRAFANA_ADMIN_PASSWORD=<choose-a-strong-password>" > .env
$ docker compose up -d
Creating network "prometheus-grafana_default" with the default driver
Creating volume "prometheus-grafana_prom_data" with default driver
...
Creating grafana    ... done
Creating prometheus ... done
Attaching to prometheus, grafana

```

## Expected result

Listing containers must show two containers running and the port mapping as below:
```
$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                    NAMES
dbdec637814f        prom/prometheus     "/bin/prometheus --c…"   8 minutes ago       Up 8 minutes        0.0.0.0:9090->9090/tcp   prometheus
79f667cb7dc2        grafana/grafana     "/bin/sh -c 'if [ -…"   8 minutes ago       Up 8 minutes        127.0.0.1:3000->3000/tcp grafana
```

Navigate to `http://localhost:3000` in your web browser and log in as `admin` with the password you set in `GRAFANA_ADMIN_PASSWORD` to access Grafana. It is already configured with prometheus as the default datasource.

![page](output.jpg)

Navigate to `http://localhost:9090` in your web browser to access directly the web interface of prometheus.

Stop and remove the containers. Use `-v` to remove the volumes if looking to erase all data.
```
$ docker compose down -v
```
