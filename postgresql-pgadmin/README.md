## PostgreSQL and pgAdmin
This example provides a base setup for using [PostgreSQL](https://www.postgresql.org/) and [pgAdmin](https://www.pgadmin.org/).
More details on how to customize the installation and the compose file can be found [here (PostgreSQL)](https://hub.docker.com/_/postgres) and [here (pgAdmin)](https://www.pgadmin.org/docs/pgadmin4/latest/container_deployment.html).

Project structure:
```
.
├── .env
├── compose.yaml
├── secrets              (created by you, not committed)
│   ├── pgadmin_password.txt
│   └── postgres_password.txt
└── README.md
```

[_compose.yaml_](compose.yaml)
``` yaml
services:
  postgres:
    image: postgres:latest
    ...
  pgadmin:
    image: dpage/pgadmin4:latest
```

## Configuration

### .env
Before deploying this setup, you need to configure the following values in the [.env](.env) file.
- POSTGRES_USER
- POSTGRES_DB (can be default value)
- PGADMIN_MAIL

### Passwords
The PostgreSQL and pgAdmin passwords are not stored in the repository. They are passed to the containers as
[Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/) read from files in a local `secrets/`
directory, which is ignored by git. Create them before the first start, for example with random values:

``` shell
$ mkdir -p secrets
$ openssl rand -base64 24 > secrets/postgres_password.txt
$ openssl rand -base64 24 > secrets/pgadmin_password.txt
```

The containers do not start until both files exist and are non-empty. The files must stay readable by the
pgAdmin container user, so do not restrict them to mode `600`. Both passwords are applied when the data is first
initialized; changing the files later does not change them.

## Deploy with docker compose
When deploying this setup, the pgAdmin web interface will be available at port 5050 (e.g. http://localhost:5050).
PostgreSQL is only reachable from other services in this compose project; its port is not published on the host.

``` shell
$ docker compose up
Starting postgres ... done
Starting pgadmin ... done
```

## Add postgres database to pgAdmin
Log in with `PGADMIN_MAIL` from the .env file and the password in `secrets/pgadmin_password.txt`. Then you can add your database to pgAdmin. 
1. Right-click "Servers" in the top-left corner and select "Create" -> "Server..."
2. Name your connection
3. Change to the "Connection" tab and add the connection details:
- Hostname: "postgres" (this would normally be your IP address of the postgres database - however, docker can resolve this container ip by its name)
- Port: "5432"
- Maintenance Database: $POSTGRES_DB (see .env)
- Username: $POSTGRES_USER (see .env)
- Password: the contents of `secrets/postgres_password.txt`
  
## Expected result

Check containers are running:
```
$ docker ps
CONTAINER ID   IMAGE                           COMMAND                  CREATED             STATUS                 PORTS                                                                                  NAMES
849c5f48f784   postgres:latest                 "docker-entrypoint.s…"   9 minutes ago       Up 9 minutes           5432/tcp                                                                               postgres
d3cde3b455ee   dpage/pgadmin4:latest           "/entrypoint.sh"         9 minutes ago       Up 9 minutes           443/tcp, 0.0.0.0:5050->80/tcp, :::5050->80/tcp                                         pgadmin
```

Stop the containers with
``` shell
$ docker compose down
# To delete all data run:
$ docker compose down -v
```
