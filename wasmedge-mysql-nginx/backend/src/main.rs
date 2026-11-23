use hyper::header::{HeaderValue, HOST, ORIGIN, VARY};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode, Server};
pub use mysql_async::prelude::*;
pub use mysql_async::*;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::result::Result;
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

const DEFAULT_ALLOWED_ORIGINS: &str = "http://localhost:8090,http://127.0.0.1:8090";
const DEFAULT_ALLOWED_HOSTS: &str = "localhost,127.0.0.1,[::1],backend";

struct AccessPolicy {
    origins: Vec<String>,
    hosts: Vec<String>,
}

impl AccessPolicy {
    fn from_env() -> Self {
        Self {
            origins: list_from_env("ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS),
            hosts: list_from_env("ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)
                .into_iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
        }
    }

    // Rejecting unknown Host names stops DNS-rebound pages from reaching the API as same-origin.
    fn host_allowed(&self, req: &Request<Body>) -> bool {
        let header_host = match req.headers().get(HOST).map(|v| v.to_str()) {
            Some(Ok(host)) => host,
            _ => return false,
        };
        if !self.is_allowed_host(header_host) {
            return false;
        }
        match req.uri().authority() {
            Some(authority) => self.is_allowed_host(authority.as_str()),
            None => true,
        }
    }

    fn is_allowed_host(&self, host_and_port: &str) -> bool {
        let host = if host_and_port.starts_with('[') {
            match host_and_port.find(']') {
                Some(end) => &host_and_port[..=end],
                None => return false,
            }
        } else {
            host_and_port.split(':').next().unwrap_or("")
        };
        let host = host.to_ascii_lowercase();
        self.hosts.iter().any(|allowed| *allowed == host)
    }

    fn is_allowed_origin(&self, origin: &str) -> bool {
        self.origins.iter().any(|allowed| allowed == origin)
    }
}

fn list_from_env(name: &str, default: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn get_url() -> String {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let opts = Opts::from_url(&url).expect("DATABASE_URL invalid");
        if opts
            .db_name()
            .expect("a database name is required")
            .is_empty()
        {
            panic!("database name is empty");
        }
        url
    } else {
        "mysql://root:pass@127.0.0.1:3306/mysql".into()
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Order {
    order_id: i32,
    product_id: i32,
    quantity: i32,
    amount: f32,
    shipping: f32,
    tax: f32,
    shipping_address: String,
}

impl Order {
    fn new(
        order_id: i32,
        product_id: i32,
        quantity: i32,
        amount: f32,
        shipping: f32,
        tax: f32,
        shipping_address: String,
    ) -> Self {
        Self {
            order_id,
            product_id,
            quantity,
            amount,
            shipping,
            tax,
            shipping_address,
        }
    }
}

async fn handle_request(
    req: Request<Body>,
    pool: Pool,
    policy: Arc<AccessPolicy>,
) -> Result<Response<Body>, anyhow::Error> {
    if !policy.host_allowed(&req) {
        return Ok(status_response(StatusCode::FORBIDDEN));
    }

    let (cors_origin, foreign_origin) = match req.headers().get(ORIGIN) {
        None => (None, false),
        Some(value) => match value.to_str() {
            Ok(origin) if policy.is_allowed_origin(origin) => (Some(value.clone()), false),
            _ => (None, true),
        },
    };

    // Browsers send Origin on every POST, so a page from another origin cannot trigger writes.
    let is_safe_method = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if foreign_origin && !is_safe_method {
        return Ok(status_response(StatusCode::FORBIDDEN));
    }

    let cors = cors_origin.as_ref();
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Ok(Response::new(Body::from(
            "The valid endpoints are /init /create_order /create_orders /update_order /orders /delete_order",
        ))),

        // Simply echo the body back to the client.
        (&Method::POST, "/echo") => Ok(Response::new(req.into_body())),

        // CORS OPTIONS
        (&Method::OPTIONS, "/init") => Ok(response_build("", cors)),
        (&Method::OPTIONS, "/create_order") => Ok(response_build("", cors)),
        (&Method::OPTIONS, "/create_orders") => Ok(response_build("", cors)),
        (&Method::OPTIONS, "/update_order") => Ok(response_build("", cors)),
        (&Method::OPTIONS, "/delete_order") => Ok(response_build("", cors)),
        (&Method::OPTIONS, "/orders") => Ok(response_build("", cors)),
        
        (&Method::POST, "/init") => {
            let mut conn = pool.get_conn().await.unwrap();
            "DROP TABLE IF EXISTS orders;".ignore(&mut conn).await?;
            "CREATE TABLE orders (order_id INT, product_id INT, quantity INT, amount FLOAT, shipping FLOAT, tax FLOAT, shipping_address VARCHAR(20));".ignore(&mut conn).await?;
            drop(conn);
            Ok(response_build("{\"status\":true}", cors))
        }

        (&Method::POST, "/create_order") => {
            let mut conn = pool.get_conn().await.unwrap();

            let byte_stream = hyper::body::to_bytes(req).await?;
            let order: Order = serde_json::from_slice(&byte_stream).unwrap();

            "INSERT INTO orders (order_id, product_id, quantity, amount, shipping, tax, shipping_address) VALUES (:order_id, :product_id, :quantity, :amount, :shipping, :tax, :shipping_address)"
                .with(params! {
                    "order_id" => order.order_id,
                    "product_id" => order.product_id,
                    "quantity" => order.quantity,
                    "amount" => order.amount,
                    "shipping" => order.shipping,
                    "tax" => order.tax,
                    "shipping_address" => &order.shipping_address,
                })
                .ignore(&mut conn)
                .await?;

            drop(conn);
            Ok(response_build("{\"status\":true}", cors))
        }

        (&Method::POST, "/create_orders") => {
            let mut conn = pool.get_conn().await.unwrap();

            let byte_stream = hyper::body::to_bytes(req).await?;
            let orders: Vec<Order> = serde_json::from_slice(&byte_stream).unwrap();

            "INSERT INTO orders (order_id, product_id, quantity, amount, shipping, tax, shipping_address) VALUES (:order_id, :product_id, :quantity, :amount, :shipping, :tax, :shipping_address)"
                .with(orders.iter().map(|order| {
                    params! {
                        "order_id" => order.order_id,
                        "product_id" => order.product_id,
                        "quantity" => order.quantity,
                        "amount" => order.amount,
                        "shipping" => order.shipping,
                        "tax" => order.tax,
                        "shipping_address" => &order.shipping_address,
                    }
                }))
                .batch(&mut conn)
                .await?;

            drop(conn);
            Ok(response_build("{\"status\":true}", cors))
        }

        (&Method::POST, "/update_order") => {
            let mut conn = pool.get_conn().await.unwrap();

            let byte_stream = hyper::body::to_bytes(req).await?;
            let order: Order = serde_json::from_slice(&byte_stream).unwrap();

            "UPDATE orders SET product_id=:product_id, quantity=:quantity, amount=:amount, shipping=:shipping, tax=:tax, shipping_address=:shipping_address WHERE order_id=:order_id"
                .with(params! {
                    "product_id" => order.product_id,
                    "quantity" => order.quantity,
                    "amount" => order.amount,
                    "shipping" => order.shipping,
                    "tax" => order.tax,
                    "shipping_address" => &order.shipping_address,
                    "order_id" => order.order_id,
                })
                .ignore(&mut conn)
                .await?;

            drop(conn);
            Ok(response_build("{\"status\":true}", cors))
        }

        (&Method::GET, "/orders") => {
            let mut conn = pool.get_conn().await.unwrap();

            let orders = "SELECT * FROM orders"
                .with(())
                .map(&mut conn, |(order_id, product_id, quantity, amount, shipping, tax, shipping_address)| {
                    Order::new(
                        order_id,
                        product_id,
                        quantity,
                        amount,
                        shipping,
                        tax,
                        shipping_address,
                    )},
                ).await?;

            drop(conn);
            Ok(response_build(serde_json::to_string(&orders)?.as_str(), cors))
        }        
        
        (&Method::POST, "/delete_order") => {
            let mut conn = pool.get_conn().await.unwrap();

            let params: HashMap<String, String> = req.uri().query().map(|v| {
                url::form_urlencoded::parse(v.as_bytes()).into_owned().collect()
            }).unwrap_or_else(HashMap::new);
            let order_id = params.get("id");

            "DELETE FROM orders WHERE order_id=:order_id"
                .with(params! { "order_id" => order_id, })
                .ignore(&mut conn)
                .await?;

            drop(conn);
            Ok(response_build("{\"status\":true}", cors))
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn status_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::default();
    *response.status_mut() = status;
    response
}

// CORS headers are only sent to origins listed in ALLOWED_ORIGINS.
fn response_build(body: &str, cors_origin: Option<&HeaderValue>) -> Response<Body> {
    let mut builder = Response::builder().header(VARY, "Origin");
    if let Some(origin) = cors_origin {
        builder = builder
            .header("Access-Control-Allow-Origin", origin.clone())
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header("Access-Control-Allow-Headers", "api,Keep-Alive,User-Agent,Content-Type");
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let opts = Opts::from_url(&*get_url()).unwrap();
    let builder = OptsBuilder::from_opts(opts);
    // The connection pool will have a min of 5 and max of 10 connections.
    let constraints = PoolConstraints::new(5, 10).unwrap();
    let pool_opts = PoolOpts::default().with_constraints(constraints);
    let pool = Pool::new(builder.pool_opts(pool_opts));
    let policy = Arc::new(AccessPolicy::from_env());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        let policy = policy.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let pool = pool.clone();
                let policy = policy.clone();
                handle_request(req, pool, policy)
            }))
        }
    });
    let server = Server::bind(&addr).serve(make_svc);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}
