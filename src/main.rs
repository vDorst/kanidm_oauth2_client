use actix_web::web::{get, post, Form, Json};
use actix_web::{get, post, web, App, HttpServer};
use std::sync::{Mutex, Arc};

use serde::{Deserialize, Serialize};

use config::Config;


use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};

use log::{error, info};

struct AppStateWithCounter {
    counter: Mutex<usize>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenBody {
    grant_type: String,
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

async fn index(data: web::Data<AppStateWithCounter>) -> String {
    let mut counter = data.counter.lock().unwrap(); // <- get counter's MutexGuard
    *counter += 1; // <- access counter inside MutexGuard

    format!("Request number: {counter}") // <- response with count
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let oauth2_settings = Config::builder()
        .add_source(config::File::with_name("oauth2.toml"))
        .add_source(config::Environment::with_prefix("OAUTH2"))
        .build()
        .unwrap();


    // Note: web::Data created _outside_ HttpServer::new closure
    let counter = web::Data::new(AppStateWithCounter {
        counter: Mutex::new(0),
    });

    let kanidm_client_id = ClientId::new(oauth2_settings.get("client_id").unwrap());
    let kanidm_client_secret =
        ClientSecret::new(oauth2_settings.get("client_secret").unwrap());
    let kanimd_auth_url = AuthUrl::new(oauth2_settings.get("auth_url").unwrap()).unwrap();
    let kanidm_token_url = TokenUrl::new(oauth2_settings.get("auth_url").unwrap()).unwrap();
        

    // Set up the config for the Github OAuth2 process.
    let client = BasicClient::new(
        kanidm_client_id,
        Some(kanidm_client_secret),
        kanimd_auth_url,
        Some(kanidm_token_url),
    )
    // This example will be running its own server at localhost:18080.
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:18080/".to_string()).expect("Invalid redirect URL"),
    );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the user's public repos and email.
        .add_scope(Scope::new("openid".to_string()))
        .url();

    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(counter.clone()) // <- register the created data
            .route("/", web::get().to(index))
    })
    .bind(("127.0.0.1", 18080))?
    .run()
    .await
}
