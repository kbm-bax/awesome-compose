# Compose sample application

![Compatible with Docker+Wasm](../icon_wasm.svg)

This sample demonstrates a web application with a WebAssembly (Wasm) microservice, written in Rust. The Wasm microservice is an HTTP API connected to a MySQL (MariaDB) database. The API is invoked via from JavaScript in a web interface serving static HTML. The microservice is compiled into WebAssembly (Wasm) and runs in the WasmEdge Runtime, a secure and lightweight alternative to natively compiled Rust apps in Linux containers. Checkout [this article](https://blog.logrocket.com/rust-microservices-server-side-webassembly/) or [this video](https://www.youtube.com/watch?v=VSqMPFr7SEs) to learn how the Rust code in this microservice works.

## WasmEdge server with Nginx proxy and MySQL database

Project structure:

```
.
+-- compose.yml
|-- backend
    +-- Dockerfile
    |-- Cargo.toml
    |-- src
        +-- main.rs
|-- frontend
    +-- index.html
    |-- js
        +-- app.js
|-- nginx
    +-- default.conf
|-- db
    +-- orders.json
    |-- update_order.json
```

The [compose.yml](compose.yml) file:

```yaml
services:
  frontend:
    image: nginx:alpine
    ports:
      - 8090:80
    volumes:
      - ./frontend:/usr/share/nginx/html
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - backend

  backend:
    image: demo-microservice
    platform: wasi/wasm
    build:
      context: backend/
    environment:
      DATABASE_URL: mysql://root:whalehello@db:3306/mysql
      ORDER_API_TOKEN: ${ORDER_API_TOKEN:?set ORDER_API_TOKEN to a long random secret}
      RUST_BACKTRACE: full
    restart: unless-stopped
    runtime: io.containerd.wasmedge.v1

  db:
    image: mariadb:10.9
    environment:
      MYSQL_ROOT_PASSWORD: whalehello
```

The compose file defines an application with three services `frontend`, `backend` and `db`. The `frontend` is a simple Nginx server that hosts static web pages and proxies requests under `/api/` to the `backend` web service, in the WasmEdge container, on the Compose network. Only port 8090 of the `frontend` service is published on the host; the `backend` and `db` services are not reachable from outside the Compose network. Make sure that port 8090 on the host is not already being used.

Every order endpoint requires the `ORDER_API_TOKEN` secret, sent as an `Authorization: Bearer` header. The backend refuses to start without it, and requests without the correct token get `401 Unauthorized` before any database access.

## Deploy with docker compose

Choose a long random value for `ORDER_API_TOKEN` and keep it out of version control, for example:

```bash
$ export ORDER_API_TOKEN="$(openssl rand -hex 32)"
$ docker compose up -d
...
 ⠿ Network wasmedge-mysql-nginx_default       Created
 ⠿ Container wasmedge-mysql-nginx-db-1        Created
 ⠿ Container wasmedge-mysql-nginx-frontend-1  Created
 ⠿ Container wasmedge-mysql-nginx-backend-1   Created
```

## Expected result

```bash
$ docker compose ps
NAME                              COMMAND                  SERVICE             STATUS              PORTS
wasmedge-mysql-nginx-backend-1    "order_demo_service.…"   backend             running
wasmedge-mysql-nginx-db-1         "docker-entrypoint.s…"   db                  running             3306/tcp
wasmedge-mysql-nginx-frontend-1   "/docker-entrypoint.…"   frontend            running             0.0.0.0:8090->80/tcp, :::8090->80/tcp
```

After the application starts, go to `http://localhost:8090` in your web browser to display the web frontend. The page asks for the `ORDER_API_TOKEN` value and keeps it in the browser tab's session storage.

### Using the API with `curl`

As an alternative to the web frontend, you can use `curl` to interact with the WasmEdge API through the `frontend` proxy at `http://localhost:8090/api/`. Every request below sends the token in the `Authorization` header.

When the WasmEdge web service receives a POST request to the `/init` endpoint, it would initialize the database with the `orders` table.

```bash
curl http://localhost:8090/api/init -X POST -H "Authorization: Bearer $ORDER_API_TOKEN"
```

When the WasmEdge web service receives a POST request to the `/create_order` endpoint, it extracts the JSON data from the POST body and inserts an `Order` record into the database table.
To insert multiple records, use the `/create_orders` endpoint and POST a JSON array of `Order` objects:

```bash
curl http://localhost:8090/api/create_orders -X POST -H "Authorization: Bearer $ORDER_API_TOKEN" -d @db/orders.json
```

When the WasmEdge web service receives a GET request to the `/orders` endpoint, it gets all rows from the `orders` table and return the result set in a JSON array in the HTTP response.

```bash
curl http://localhost:8090/api/orders -H "Authorization: Bearer $ORDER_API_TOKEN"
```

When the WasmEdge web service receives a POST request to the `/update_order` endpoint, it extracts the JSON data from the POST body and update the `Order` record in the database table that matches the `order_id` in the input data.

```bash
curl http://localhost:8090/api/update_order -X POST -H "Authorization: Bearer $ORDER_API_TOKEN" -d @db/update_order.json
```

When the WasmEdge web service receives a POST request to the `/delete_order` endpoint, it deletes the row in the `orders` table that matches the `id` query parameter.

```bash
curl "http://localhost:8090/api/delete_order?id=2" -X POST -H "Authorization: Bearer $ORDER_API_TOKEN"
```
