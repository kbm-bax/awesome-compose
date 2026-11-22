use hyper::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
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

fn get_api_token() -> String {
    match std::env::var("ORDER_API_TOKEN") {
        Ok(token) if !token.is_empty() => token,
        _ => panic!("ORDER_API_TOKEN must be set to a non-empty secret"),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_authorized(req: &Request<Body>, api_token: &str) -> bool {
    let mut values = req.headers().get_all(AUTHORIZATION).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value.as_bytes(),
        _ => return false,
    };
    const SCHEME: &[u8] = b"Bearer ";
    if value.len() <= SCHEME.len() || !value[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        return false;
    }
    constant_time_eq(&value[SCHEME.len()..], api_token.as_bytes())
}

fn unauthorized() -> Response<Body> {
    let mut response = response_build("{\"status\":false,\"error\":\"unauthorized\"}");
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn bad_request(error: &str) -> Response<Body> {
    let body = serde_json::json!({ "status": false, "error": error }).to_string();
    let mut response = response_build(&body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

async fn handle_request(req: Request<Body>, pool: Pool, api_token: Arc<String>) -> Result<Response<Body>, anyhow::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            return Ok(Response::new(Body::from(
                "The valid endpoints are /init /create_order /create_orders /update_order /orders /delete_order",
            )))
        }

        // Simply echo the body back to the client.
        (&Method::POST, "/echo") => return Ok(Response::new(req.into_body())),

        // CORS OPTIONS
        (&Method::OPTIONS, "/init")
        | (&Method::OPTIONS, "/create_order")
        | (&Method::OPTIONS, "/create_orders")
        | (&Method::OPTIONS, "/update_order")
        | (&Method::OPTIONS, "/delete_order")
        | (&Method::OPTIONS, "/orders") => return Ok(response_build("")),

        _ => {}
    }

    // Every remaining route reads or writes orders, so the caller must
    // present the API token before the body is read or a connection is taken.
    if !is_authorized(&req, &api_token) {
        return Ok(unauthorized());
    }

    match (req.method(), req.uri().path()) {
        (&Method::POST, "/init") => {
            let mut conn = pool.get_conn().await.unwrap();
            "DROP TABLE IF EXISTS orders;".ignore(&mut conn).await?;
            "CREATE TABLE orders (order_id INT, product_id INT, quantity INT, amount FLOAT, shipping FLOAT, tax FLOAT, shipping_address VARCHAR(20));".ignore(&mut conn).await?;
            drop(conn);
            Ok(response_build("{\"status\":true}"))
        }

        (&Method::POST, "/create_order") => {
            let byte_stream = hyper::body::to_bytes(req).await?;
            let order: Order = match serde_json::from_slice(&byte_stream) {
                Ok(order) => order,
                Err(_) => return Ok(bad_request("invalid order JSON")),
            };

            let mut conn = pool.get_conn().await.unwrap();

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
            Ok(response_build("{\"status\":true}"))
        }

        (&Method::POST, "/create_orders") => {
            let byte_stream = hyper::body::to_bytes(req).await?;
            let orders: Vec<Order> = match serde_json::from_slice(&byte_stream) {
                Ok(orders) => orders,
                Err(_) => return Ok(bad_request("invalid orders JSON")),
            };

            let mut conn = pool.get_conn().await.unwrap();

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
            Ok(response_build("{\"status\":true}"))
        }

        (&Method::POST, "/update_order") => {
            let byte_stream = hyper::body::to_bytes(req).await?;
            let order: Order = match serde_json::from_slice(&byte_stream) {
                Ok(order) => order,
                Err(_) => return Ok(bad_request("invalid order JSON")),
            };

            let mut conn = pool.get_conn().await.unwrap();

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
            Ok(response_build("{\"status\":true}"))
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
            Ok(response_build(serde_json::to_string(&orders)?.as_str()))
        }        
        
        (&Method::POST, "/delete_order") => {
            let params: HashMap<String, String> = req.uri().query().map(|v| {
                url::form_urlencoded::parse(v.as_bytes()).into_owned().collect()
            }).unwrap_or_else(HashMap::new);
            let order_id = match params.get("id").and_then(|id| id.parse::<i32>().ok()) {
                Some(order_id) => order_id,
                None => return Ok(bad_request("a numeric id is required")),
            };

            let mut conn = pool.get_conn().await.unwrap();

            "DELETE FROM orders WHERE order_id=:order_id"
                .with(params! { "order_id" => order_id, })
                .ignore(&mut conn)
                .await?;

            drop(conn);
            Ok(response_build("{\"status\":true}"))
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

// CORS headers
fn response_build(body: &str) -> Response<Body> {
    Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header("Access-Control-Allow-Headers", "api,Keep-Alive,User-Agent,Content-Type")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let api_token = Arc::new(get_api_token());
    let opts = Opts::from_url(&*get_url()).unwrap();
    let builder = OptsBuilder::from_opts(opts);
    // The connection pool will have a min of 5 and max of 10 connections.
    let constraints = PoolConstraints::new(5, 10).unwrap();
    let pool_opts = PoolOpts::default().with_constraints(constraints);
    let pool = Pool::new(builder.pool_opts(pool_opts));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        let api_token = api_token.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let pool = pool.clone();
                let api_token = api_token.clone();
                handle_request(req, pool, api_token)
            }))
        }
    });
    let server = Server::bind(&addr).serve(make_svc);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}
