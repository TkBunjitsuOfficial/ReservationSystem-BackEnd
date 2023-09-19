use crate::lambda_runtime::Error;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::{AttributeValue, ReturnValue, Select};
use aws_sdk_dynamodb::Client as DdbClient;
use aws_types::region::Region;
use lambda_http::{
    handler,
    http::{response::Builder, Method, StatusCode},
    lambda_runtime::{self, Context},
    Body, IntoResponse, Request, Response,
};
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
struct RecaptchaResSt {
    success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct RegisterRequestSt {
    guest_name: String,
    email: String,
    phone: String,
    time_id: usize,
    gender: usize,
    age: usize,
    guest_type: usize,
    #[serde(default)]
    student_grade: Option<usize>,
    #[serde(default)]
    student_class: Option<usize>,
    #[serde(default)]
    student_number: Option<usize>,
    #[serde(default)]
    student_name: Option<String>,
    recaptcha_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UnregisterRequestSt {
    guest_id: String,
    phone: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CheckRequestSt {
    guest_id: String,
    phone: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ReceptionRequestSt {
    guest_id: String,
}

//const RECAPTCHA_SECRET_KEY: &str = "{HERE COMES THE KEY}";
const COUNTER_LIST: [&str; 12] = [
    "counter_Day1A",
    "counter_Day1B",
    "counter_Day1C",
    "counter_Day1D",
    "counter_Day2A",
    "counter_Day2B",
    "counter_Day2C",
    "counter_Day2D",
    "counter_Day3A",
    "counter_Day3B",
    "counter_Day3C",
    "counter_Day3D",
];
const ID_LIST: [&str; 12] = [
    "nextid_Day1A",
    "nextid_Day1B",
    "nextid_Day1C",
    "nextid_Day1D",
    "nextid_Day2A",
    "nextid_Day2B",
    "nextid_Day2C",
    "nextid_Day2D",
    "nextid_Day3A",
    "nextid_Day3B",
    "nextid_Day3C",
    "nextid_Day3D",
];
const TABLE_NAME: &str = "guests";
const COUNTER_TABLE_NAME: &str = "counter_table";

async fn func(request: Request, _: Context) -> Result<impl IntoResponse, Error> {
    println!("{}", request.uri());
    match request.body() {
        Body::Text(t) => println!("{}", t),
        Body::Empty => println!("Empty"),
        Body::Binary(_b) => println!("Binary"),
    };

    Ok(match request.uri().path() {
        "/register" => match request.method() {
            &Method::OPTIONS => process_preflight().await,
            &Method::POST => {
                let request_json: RegisterRequestSt = match request.body() {
                    Body::Text(t) => match serde_json::from_str(t) {
                        Ok(v) => v,
                        Err(_) => return bad_request("Failed to convert request text to json"),
                    },
                    _ => return bad_request("Request doesn't consist of text"),
                };
                let RegisterRequestSt {
                    guest_name,
                    email,
                    phone,
                    time_id,
                    gender,
                    age,
                    guest_type,
                    student_grade,
                    student_class,
                    student_number,
                    student_name,
                    recaptcha_token,
                } = request_json;
                match recaptcha_check(&recaptcha_token).await {
                    Ok(success) => {
                        if success {
                            register_user(
                                &guest_name,
                                &email,
                                &phone,
                                time_id,
                                gender,
                                age,
                                guest_type,
                                student_grade,
                                student_class,
                                student_number,
                                student_name,
                            )
                            .await
                        } else {
                            bad_request("")
                        }
                    }
                    Err(resp) => resp,
                }
            }
            _ => not_found(),
        },
        "/unregister" => match request.method() {
            &Method::OPTIONS => process_preflight().await,
            &Method::POST => {
                let request_json: UnregisterRequestSt = match request.body() {
                    Body::Text(t) => match serde_json::from_str(t) {
                        Ok(v) => v,
                        Err(_) => return bad_request("Failed to convert request text to json"),
                    },
                    _ => return bad_request("Request doesn't consist of text"),
                };
                let UnregisterRequestSt { guest_id, phone } = request_json;
                unregister_user(&guest_id, &phone).await
            }
            _ => not_found(),
        },
        "/check_available" => match request.method() {
            &Method::OPTIONS => process_preflight().await,
            &Method::GET => check_available().await,
            _ => not_found(),
        },
        "/check_id" => match request.method() {
            &Method::OPTIONS => process_preflight().await,
            &Method::POST => {
                let request_json: CheckRequestSt = match request.body() {
                    Body::Text(t) => match serde_json::from_str(t) {
                        Ok(v) => v,
                        Err(_) => return bad_request("Failed to convert request text to json"),
                    },
                    _ => return bad_request("Request doesn't consist of text"),
                };
                let CheckRequestSt { guest_id, phone } = request_json;
                check_id(&guest_id, &phone).await
            }
            _ => not_found(),
        },
        "/reception" => match request.method() {
            &Method::OPTIONS => process_preflight().await,
            &Method::POST => {
                let request_json: ReceptionRequestSt = match request.body() {
                    Body::Text(t) => match serde_json::from_str(t) {
                        Ok(v) => v,
                        Err(_) => return bad_request("Failed to convert request text to json"),
                    },
                    _ => return bad_request("Request doesn't consist of text"),
                };
                let ReceptionRequestSt { guest_id } = request_json;
                enter_user(&guest_id).await
            }
            _ => not_found(),
        },
        _ => not_found(),
    }?)
}

fn cors_headers_attached_response(
    status: StatusCode,
    origin: &str,
    methods: &str,
    headers: &str,
) -> Builder {
    Builder::new()
        .status(status)
        .header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Methods", methods)
        .header("Access-Control-Allow-Headers", headers)
}

async fn recaptcha_check(recaptcha_token: &str) -> Result<bool, Result<Response<Body>, Error>> {
    let client = reqwest::Client::new();
    let recaptcha_res = match client
        .get(format!(
            "https://www.google.com/recaptcha/api/siteverify?secret={}&response={}",
            RECAPTCHA_SECRET_KEY, recaptcha_token
        ))
        .send()
        .await
    {
        Ok(v) => v,
        Err(_) => return Err(internal_error("Failed to verify recaptcha token")),
    };
    let recaptcha_res_json: RecaptchaResSt =
        match serde_json::from_str(&match recaptcha_res.text().await {
            Ok(v) => {
                println!("{}", v);
                v
            }
            Err(_) => return Err(internal_error("Failed to get text from recaptcha response")),
        }) {
            Ok(v) => v,
            Err(_) => {
                return Err(internal_error(
                    "Failed to convert recaptcha response to json",
                ))
            }
        };

    Ok(recaptcha_res_json.success)
}

async fn process_preflight() -> Result<Response<Body>, Error> {
    println!("process_preflight called");

    Ok(
        match cors_headers_attached_response(StatusCode::OK, "*", "OPTIONS, GET, POST", "*")
            .body(Body::Text("".to_string()))
        {
            Ok(v) => v,
            Err(_) => return bad_request("Failed to build response"),
        },
    )
}

fn generate_checkdigits() -> String {
    format!("{:0>3}", rand::thread_rng().gen_range(0..1000))
}

async fn register_user(
    guest_name: &str,
    email: &str,
    phone: &str,
    time_id: usize,
    gender: usize,
    age: usize,
    guest_type: usize,
    student_grade: Option<usize>,
    student_class: Option<usize>,
    student_number: Option<usize>,
    student_name: Option<String>,
) -> Result<Response<Body>, Error> {
    println!("register_user called");

    let region_provider = RegionProviderChain::first_try(Region::new("ap-northeast-1"));
    let shared_config = aws_config::from_env().region(region_provider).load().await;
    let client = DdbClient::new(&shared_config);

    let get_id_req = client
        .update_item()
        .table_name(COUNTER_TABLE_NAME)
        .return_values(ReturnValue::AllNew)
        .key("name", AttributeValue::S(ID_LIST[time_id].into()))
        .update_expression("ADD #value :incr")
        .expression_attribute_names("#value", "value")
        .expression_attribute_values(":incr", AttributeValue::N(1.to_string()));
    println!("Issuing new guest_id...");
    let get_id_req_resp = match get_id_req.send().await {
        Ok(v) => v,
        Err(e) => return internal_error(&e.to_string()),
    };
    let id_item = match get_id_req_resp.attributes() {
        Some(v) => v,
        None => return internal_error("Failed to get attributes of the counter"),
    };

    let inc_counter_req = client
        .update_item()
        .table_name(COUNTER_TABLE_NAME)
        .key("name", AttributeValue::S(COUNTER_LIST[time_id].into()))
        .update_expression("ADD #value :incr")
        .expression_attribute_names("#value", "value")
        .expression_attribute_values(":incr", AttributeValue::N(1.to_string()));
    println!("Incrementing guest counter...");
    if let Err(e) = inc_counter_req.send().await {
        return internal_error(&e.to_string());
    }

    let guest_id = &("D".to_string()
        + &(time_id / 4 + 1).to_string()
        + &(char::from((time_id % 4) as u8 + 'A' as u8)).to_string()
        + &format!(
            "{:0>4}",
            match match id_item.get("value") {
                Some(v) => v,
                None => return internal_error("Failed to get reservation counter value"),
            }
            .as_n()
            {
                Ok(v) => v,
                Err(_) => return internal_error("Failed to parse reservation counter value"),
            }
        )
        + &generate_checkdigits());

    let mut register_guest_req = client
        .put_item()
        .table_name(TABLE_NAME)
        .item("guest_id", AttributeValue::S(guest_id.into()))
        .item("guest_name", AttributeValue::S(guest_name.into()))
        .item("email", AttributeValue::S(email.into()))
        .item("phone", AttributeValue::S(phone.into()))
        .item("time_id", AttributeValue::N(time_id.to_string()))
        .item("gender", AttributeValue::N(gender.to_string()))
        .item("age", AttributeValue::N(age.to_string()))
        .item("guest_type", AttributeValue::N(guest_type.to_string()))
        .item("enabled", AttributeValue::Bool(true));

    match student_grade {
        Some(v) => {
            register_guest_req =
                register_guest_req.item("student_grade", AttributeValue::N(v.to_string()))
        }
        None => (),
    }
    match student_class {
        Some(v) => {
            register_guest_req =
                register_guest_req.item("student_class", AttributeValue::N(v.to_string()))
        }
        None => (),
    }
    match student_number {
        Some(v) => {
            register_guest_req =
                register_guest_req.item("student_grade", AttributeValue::N(v.to_string()))
        }
        None => (),
    }
    match student_name {
        Some(v) => {
            register_guest_req =
                register_guest_req.item("student_name", AttributeValue::S(v.to_string()))
        }
        None => (),
    }
    println!(
        "Executing request [{:?}] to add item...",
        register_guest_req
    );

    if let Err(e) = register_guest_req.send().await {
        return internal_error(&e.to_string());
    }

    Ok(
        match cors_headers_attached_response(StatusCode::OK, "*", "OPTIONS, GET, POST", "*").body(
            Body::Text(json!({ "guest_id": guest_id.to_string() }).to_string()),
        ) {
            Ok(v) => v,
            Err(e) => return internal_error(&e.to_string()),
        },
    )
}

async fn unregister_user(guest_id: &str, phone: &str) -> Result<Response<Body>, Error> {
    println!("unregister_user called");

    let region_provider = RegionProviderChain::first_try(Region::new("ap-northeast-1"));
    let shared_config = aws_config::from_env().region(region_provider).load().await;
    let client = DdbClient::new(&shared_config);

    println!("Getting info of specified user...");
    let time_id: usize = match client
        .get_item()
        .table_name(TABLE_NAME)
        .key("guest_id", AttributeValue::S(guest_id.to_string()))
        .send()
        .await
    {
        Ok(get_item_output) => match get_item_output.item {
            Some(item) => {
                match item.get("enabled") {
                    Some(flag) => {
                        if match flag.as_bool() {
                            Ok(v) => v,
                            Err(_) => return internal_error("Failed to parse enabled flag"),
                        } == &false
                        {
                            return not_found();
                        }
                    }
                    None => return internal_error("Failed to get enabled flag"),
                }
                match item.get("phone") {
                    Some(number) => {
                        if match number.as_s() {
                            Ok(v) => v,
                            Err(_) => return internal_error("Failed to parse phone number"),
                        } != phone
                        {
                            return not_found();
                        }
                    }
                    None => return internal_error("Failed to get phone number"),
                }
                match item.get("time_id") {
                    Some(id) => match match id.as_n() {
                        Ok(v) => v,
                        Err(_) => return internal_error("Failed to parse time_id"),
                    }
                    .parse::<usize>()
                    {
                        Ok(v) => v,
                        Err(_) => return internal_error("Failed to parse time_id"),
                    },
                    None => return internal_error("Failed to get time_id"),
                }
            }
            None => return not_found(),
        },
        Err(e) => return internal_error(&e.to_string()),
    };

    println!("Disabling the guest_id...");
    if let Err(e) = client
        .update_item()
        .table_name(TABLE_NAME)
        .key("guest_id", AttributeValue::S(guest_id.to_string()))
        .update_expression("SET #enabled = :false")
        .expression_attribute_names("#enabled", "enabled")
        .expression_attribute_values(":false", AttributeValue::Bool(false))
        .send()
        .await
    {
        return internal_error(&e.to_string());
    }

    println!("Decrementing the guest count...");
    if let Err(e) = client
        .update_item()
        .table_name(COUNTER_TABLE_NAME)
        .key("name", AttributeValue::S(COUNTER_LIST[time_id].into()))
        .update_expression("ADD #value :incr")
        .expression_attribute_names("#value", "value")
        .expression_attribute_values(":incr", AttributeValue::N((-1).to_string()))
        .send()
        .await
    {
        return internal_error(&e.to_string());
    }

    Ok(
        match cors_headers_attached_response(StatusCode::OK, "*", "OPTIONS, GET, POST", "*").body(
            Body::Text(json!({ "guest_id": guest_id.to_string() }).to_string()),
        ) {
            Ok(v) => v,
            Err(e) => return internal_error(&e.to_string()),
        },
    )
}

const DUPLICATES: [u32; 12] = [32, 7, 4, 10, 54, 16, 7, 25, 61, 15, 5, 12];
async fn check_available() -> Result<Response<Body>, Error> {
    println!("check_available called");

    let region_provider = RegionProviderChain::first_try(Region::new("ap-northeast-1"));
    let shared_config = aws_config::from_env().region(region_provider).load().await;
    let client = DdbClient::new(&shared_config);

    println!("Checking the numbers of reservation");

    match client
        .scan()
        .table_name(COUNTER_TABLE_NAME)
        .filter_expression("begins_with (#name, :prefix)")
        .expression_attribute_names("#name", "name")
        .expression_attribute_values(":prefix", AttributeValue::S("counter".to_string()))
        .select(Select::AllAttributes)
        .send()
        .await
    {
        Ok(v) => match v.items() {
            Some(items) => {
                let mut map: HashMap<&str, u32> = HashMap::new();
                for item in items {
                    map.insert(
                        item.get("name").unwrap().as_s().unwrap(),
                        item.get("value").unwrap().as_n().unwrap().parse().unwrap(),
                    );
                }

                let mut res: Vec<bool> = vec![];
                for (idx, name) in COUNTER_LIST.iter().enumerate() {
                    res.push(*map.get(name).unwrap() < 1000 + DUPLICATES[idx] && idx < 4);
                }

                let available_array: [bool; 12] = match res.as_slice().try_into() {
                    Ok(v) => v,
                    Err(e) => return internal_error(&e.to_string()),
                };
                Ok(
                    cors_headers_attached_response(StatusCode::OK, "*", "OPTIONS, GET, POST", "*")
                        .body(Body::Text(json!(available_array).to_string()))?,
                )
            }
            None => return internal_error("Failed to get numbers of reservation"),
        },
        Err(e) => return internal_error(&e.to_string()),
    }
}

async fn enter_user(guest_id: &str) -> Result<Response<Body>, Error> {
    println!("enter_user called");

    let region_provider = RegionProviderChain::first_try(Region::new("ap-northeast-1"));
    let shared_config = aws_config::from_env().region(region_provider).load().await;
    let client = DdbClient::new(&shared_config);

    let item = match client
        .get_item()
        .table_name(TABLE_NAME)
        .key("guest_id", AttributeValue::S(guest_id.to_string()))
        .send()
        .await
    {
        Ok(v) => match v.item {
            Some(v) => v,
            None => return not_found(),
        },
        Err(e) => return internal_error(&e.to_string()),
    };

    if item.get("enabled").unwrap().as_bool().unwrap() == &false {
        return not_found();
    }

    if item
        .get("come")
        .unwrap_or(&AttributeValue::Bool(false))
        .as_bool()
        .unwrap()
        == &true
    {
        return not_found();
    }

    if let Err(e) = client
        .update_item()
        .table_name(TABLE_NAME)
        .key("guest_id", AttributeValue::S(guest_id.to_string()))
        .update_expression("SET #come = :true")
        .expression_attribute_names("#come", "come")
        .expression_attribute_values(":true", AttributeValue::Bool(true))
        .send()
        .await
    {
        return internal_error(&e.to_string());
    }

    Ok(
        cors_headers_attached_response(StatusCode::OK, "*", "OPTIONS, GET, POST", "*").body(
            Body::Text(json!({ "guest_id": guest_id.to_string() }).to_string()),
        )?,
    )
}

async fn check_id(guest_id: &str, phone: &str) -> Result<Response<Body>, Error> {
    println!("check_id called");

    let region_provider = RegionProviderChain::first_try(Region::new("ap-northeast-1"));
    let shared_config = aws_config::from_env().region(region_provider).load().await;
    let client = DdbClient::new(&shared_config);

    println!("Getting info of specified user...");
    let user_item = match client
        .get_item()
        .table_name(TABLE_NAME)
        .key("guest_id", AttributeValue::S(guest_id.to_string()))
        .send()
        .await
    {
        Ok(v) => match v.item {
            Some(item) => item,
            None => return not_found(),
        },
        Err(e) => return internal_error(&e.to_string()),
    };

    println!("Validating the phone number...");
    let correct_phone = user_item.get("phone").unwrap().as_s().unwrap();
    if phone != correct_phone {
        println!("The phone number was incorrect");
        return not_found();
    }

    println!("Ensuring the user is enabled...");
    let enabled = user_item.get("enabled").unwrap().as_bool().unwrap();
    if enabled != &true {
        println!("The user is disabled");
        return not_found();
    }

    let guest_name = user_item.get("guest_name").unwrap().as_s().unwrap();
    let time_id = user_item.get("time_id").unwrap().as_n().unwrap();
    Ok(
        cors_headers_attached_response(StatusCode::OK, "*", "OPTIONS, GET, POST", "*").body(
            Body::Text(json!({"guest_name": guest_name, "time_id": time_id}).to_string()),
        )?,
    )
}

fn not_found() -> Result<Response<Body>, Error> {
    println!("not_found called");
    Ok(
        cors_headers_attached_response(StatusCode::NOT_FOUND, "*", "OPTIONS, GET, POST", "*")
            .body(Body::Text("".to_string()))?,
    )
}

fn bad_request(message: &str) -> Result<Response<Body>, Error> {
    println!("bad_request called: {}", message);
    Ok(
        cors_headers_attached_response(StatusCode::BAD_REQUEST, "*", "OPTIONS, GET, POST", "*")
            .body(Body::Text("".to_string()))?,
    )
}

fn internal_error(message: &str) -> Result<Response<Body>, Error> {
    println!("internal_error called: {}", message);
    Ok(cors_headers_attached_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "*",
        "OPTIONS, GET, POST",
        "*",
    )
    .body(Body::Text("".to_string()))?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::run(handler(func)).await?;
    Ok(())
}
