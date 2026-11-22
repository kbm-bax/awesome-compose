use hyper::body::HttpBody;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode, Server};
pub use mysql_async::prelude::*;
pub use mysql_async::*;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::result::Result;
use std::collections::HashMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// A panic aborts the whole process on wasm32-wasi, so request bodies must be
// bounded and parse failures must turn into responses, never unwraps.
const MAX_BODY_BYTES: usize = 64 * 1024;

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

async fn handle_request(req: Request<Body>, pool: Pool) -> Result<Response<Body>, anyhow::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Ok(Response::new(Body::from(
            "The valid endpoints are /init /create_order /create_orders /update_order /orders /delete_order",
        ))),

        // Simply echo the body back to the client.
        (&Method::POST, "/echo") => Ok(Response::new(req.into_body())),

        // CORS OPTIONS
        (&Method::OPTIONS, "/init") => Ok(response_build(&String::from(""))),
        (&Method::OPTIONS, "/create_order") => Ok(response_build(&String::from(""))),
        (&Method::OPTIONS, "/create_orders") => Ok(response_build(&String::from(""))),
        (&Method::OPTIONS, "/update_order") => Ok(response_build(&String::from(""))),
        (&Method::OPTIONS, "/delete_order") => Ok(response_build(&String::from(""))),
        (&Method::OPTIONS, "/orders") => Ok(response_build(&String::from(""))),
        
        (&Method::GET, "/init") => {
            let mut conn = pool.get_conn().await?;
            "DROP TABLE IF EXISTS orders;".ignore(&mut conn).await?;
            "CREATE TABLE orders (order_id INT, product_id INT, quantity INT, amount FLOAT, shipping FLOAT, tax FLOAT, shipping_address VARCHAR(20));".ignore(&mut conn).await?;
            drop(conn);
            Ok(response_build("{\"status\":true}"))
        }

        (&Method::POST, "/create_order") => {
            let order: Order = match read_json(req).await {
                Ok(order) => order,
                Err(resp) => return Ok(resp),
            };
            let mut conn = pool.get_conn().await?;

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
            let orders: Vec<Order> = match read_json(req).await {
                Ok(orders) => orders,
                Err(resp) => return Ok(resp),
            };
            if orders.is_empty() {
                return Ok(error_response(StatusCode::BAD_REQUEST, "expected at least one order"));
            }
            let mut conn = pool.get_conn().await?;

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
            let order: Order = match read_json(req).await {
                Ok(order) => order,
                Err(resp) => return Ok(resp),
            };
            let mut conn = pool.get_conn().await?;

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
            let mut conn = pool.get_conn().await?;

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
        
        (&Method::GET, "/delete_order") => {
            let mut conn = pool.get_conn().await?;

            let params: HashMap<String, String> = req.uri().query().map(|v| {
                url::form_urlencoded::parse(v.as_bytes()).into_owned().collect()
            }).unwrap_or_else(HashMap::new);
            let order_id = params.get("id");

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

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut resp = response_build(&serde_json::json!({ "status": false, "error": message }).to_string());
    *resp.status_mut() = status;
    resp
}

async fn read_json<T: DeserializeOwned>(req: Request<Body>) -> Result<T, Response<Body>> {
    let too_large = || error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    let mut body = req.into_body();
    if body.size_hint().lower() > MAX_BODY_BYTES as u64 {
        return Err(too_large());
    }
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| error_response(StatusCode::BAD_REQUEST, "failed to read request body"))?;
        if buf.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(too_large());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("invalid order JSON: {}", e)))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let opts = Opts::from_url(&*get_url()).unwrap();
    let builder = OptsBuilder::from_opts(opts);
    // The connection pool will have a min of 5 and max of 10 connections.
    let constraints = PoolConstraints::new(5, 10).unwrap();
    let pool_opts = PoolOpts::default().with_constraints(constraints);
    let pool = Pool::new(builder.pool_opts(pool_opts));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let pool = pool.clone();
                handle_request(req, pool)
            }))
        }
    });
    let server = Server::bind(&addr).serve(make_svc);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}
