use lambda_http::{run, service_fn, Body, Error, Request, Response};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb as dynamodb;
use serde::Deserialize;
use std::collections::HashMap;

use common::{
    compute_verifying_hash,
    respond_error,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", content = "body")]
pub enum AuthEndpoint {
    Post(NewSessionRequest),
}

#[derive(Clone, Debug, Deserialize)]
pub struct NewSessionRequest {
    pub username: String,
    pub password: String,
}

impl NewSessionRequest {
    fn into_parts(self) -> (String, String) {
        (self.username, self.password)
    }
}

fn respond_ok() -> Result<Response<Body>, Error> {
    let jwt_token = "XYZ123";
    let response_message = format!("{{\"token\": \"{}\"}}", jwt_token).to_string();
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(response_message.into())
        .map_err(Box::new)?)
}

async fn handle_new_session(client: &dynamodb::Client, session_request: NewSessionRequest)
    -> Result<Response<Body>, Error> {

    let (username, password) = session_request.into_parts();

    let get_item_response = client.get_item()
        .table_name("UserAuthentication")
        .key("username", dynamodb::types::AttributeValue::S(username))
        .attributes_to_get("salt")
        .attributes_to_get("verifier")
        .send()
        .await;
    
    let mut dynamo_response = match get_item_response {
        Ok(get_item_output) => get_item_output,
        // TODO: Handle different SDK errors gracefully instead of one size fits all
        Err(err) => {
            return respond_error(503, &format!("Temporary error; Could not read from user authentication table. {:?}", err));
        }
    };
    
    let mut user_authorization_metadata: HashMap<String, AttributeValue> = if let Some(found_user) = dynamo_response.item.take() {
        found_user
    } else {
        return respond_error(404, "User doesn't exist");
    };

    let user_salt: [u8; 16] = if let Some(AttributeValue::B(salt_blob)) = user_authorization_metadata.remove("salt") {
        match salt_blob.into_inner().try_into() {
            Ok(user_salt) => user_salt,
            Err(_) => {
                return respond_error(500, "Salt length error");
            }
        }
    } else {
        return respond_error(500, "Internal error");
    };
    
    let verifier: Vec<u8> = if let Some(AttributeValue::B(verifier_blob)) = user_authorization_metadata.remove("verifier") {
        verifier_blob.into_inner()
    } else {
        return respond_error(500, "Internal error");
    };
    
    let hash = compute_verifying_hash(user_salt, password);
    if verifier == hash {
        respond_ok()
    } else {
        respond_error(401, "Incorrect password")
    }
}

async fn handle_auth(client: &dynamodb::Client, event: Request) -> Result<Response<Body>, Error> {
    let body = std::str::from_utf8(event.body())
        .expect("invalid utf-8 sequence");
    
    match serde_json::from_str::<AuthEndpoint>(body) {
        Ok(AuthEndpoint::Post(session_request)) => handle_new_session(client, session_request).await,
        Err(_) => respond_error(400, &format!("Deserialization error: {}", body)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();
    
    let config = aws_config::load_from_env().await;
    let client = dynamodb::Client::new(&config);

    run(service_fn(|event: Request| async {
        handle_auth(&client, event).await
    }))
    .await
}
