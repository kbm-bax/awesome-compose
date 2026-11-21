use serde::{Deserialize, Serialize};

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

// Body of Order::transform in ../../etl/src/main.rs. The test harness checks
// that the format string below still matches that file before compiling this.
fn transform(inbound_data: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(inbound_data).map_err(|e| e.to_string())?;
    let order: Order = serde_json::from_str(s).map_err(|e| e.to_string())?;
    let sql_string = format!(
        r"INSERT INTO orders VALUES ({:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, CURRENT_TIMESTAMP);",
        order.order_id,
        order.product_id,
        order.quantity,
        order.amount,
        order.shipping,
        order.tax,
        order.shipping_address,
    );
    Ok(sql_string)
}

fn main() {
    let raw = std::env::args().nth(1).expect("json payload");
    println!("{}", transform(raw.as_bytes()).expect("transform"));
}
