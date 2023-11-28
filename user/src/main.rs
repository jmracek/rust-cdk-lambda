use lambda_http::{run, service_fn, Body, Error, Request, Response};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb as dynamodb;
use common::{
    compute_verifying_hash,
    generate_salt,
    respond_error,
};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", content = "body")]
pub enum UserEndpoint {
    Post(CreateUserRequest),
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

impl CreateUserRequest {
    fn into_parts(self) -> (String, String) {
        (self.username, self.password)
    }
}

fn respond_ok() -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(201)
        .header("content-type", "application/json")
        .body("".into())
        .map_err(Box::new)?)
}

async fn is_existing_user(client: &dynamodb::Client, username: String) -> Result<bool, Response<Body>> {
    let get_item_response = client.get_item()
        .table_name("UserAuthentication")
        .key("username", AttributeValue::S(username))
        .send()
        .await;

    // Ensure that the response from DynamoDB is ok 
    let dynamo_response = match get_item_response {
        Ok(get_item_output) => get_item_output,
        // TODO: Handle different SDK errors gracefully instead of one size fits all
        Err(err) => {
            let error_message = format!("Temporary error; Could not read from user authentication table. {:?}", err);
            return Err(respond_error(503, &error_message).unwrap());
        }
    };

    Ok(dynamo_response.item().is_some())
}

async fn handle_new_user(client: &dynamodb::Client, create_user_request: CreateUserRequest)
    -> Result<Response<Body>, Error> {
    let (username, password) = create_user_request.into_parts();
    
    match is_existing_user(client, username.clone()).await {
        Ok(false) => (),
        Ok(true) => {
            return respond_error(409, "Chosen username is unavailable.");
        }
        Err(dynamo_error) => {
            return Ok(dynamo_error);
        }
    }

    let user_salt: [u8; 16] = generate_salt();
    let verifier: [u8; 24] = compute_verifying_hash(user_salt, password);

    tracing::info!("verifying hash complete");
    
    let dynamodb_response = client
        .put_item()
        .table_name("UserAuthentication")
        .condition_expression("attribute_not_exists(username)")
        .item("username", AttributeValue::S(username))
        .item("salt", AttributeValue::B(Blob::new(user_salt.to_vec())))
        .item("verifier", AttributeValue::B(Blob::new(verifier.to_vec())))
        .send()
        .await;
    
    match dynamodb_response {
        Ok(_) => {
            respond_ok()
        }
        Err(SdkError::ServiceError(err)) => {
            match err.into_err() {
                PutItemError::ConditionalCheckFailedException(_) => {
                    respond_error(409, "Chosen username is unavailable")
                }
                _ => {
                    respond_error(502, "Error communicating with user authentication database")
                }
            }
        }
        Err(err) => {
            respond_error(500, &format!("Internal error: {:?}", err))
        }
    }
}

async fn handle_auth(client: &dynamodb::Client, event: Request) -> Result<Response<Body>, Error> {
    let body = std::str::from_utf8(event.body())
        .expect("invalid utf-8 sequence");
    
    match serde_json::from_str::<UserEndpoint>(body) {
        Ok(UserEndpoint::Post(create_user_request)) => handle_new_user(client, create_user_request).await,
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
