#![allow(unused_imports)]
#![allow(dead_code)]

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::dev::{Service, ServiceRequest, Transform};
use actix_web::http::{header, Error};
use actix_web::web::{get, resource};
use actix_web::{cookie::Key, dev::Service as _, middleware};
use actix_web::{web, App, HttpResponse, HttpServer};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use config::Config;

use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};

use async_session::{MemoryStore, Session, SessionStore};

use log::{error, info};

use futures_util::future::FutureExt;

// pub fn validate_session(session: &Session) -> Result<(), HttpResponse> {
//     let user_id: Option<bool> = session.get("login").unwrap_or(None);

//     match user_id {
//         Some(true) => {
//             // keep the user's session alive
//             session.renew();
//             Ok(())
//         }
//         Some(_) | None => Err(HttpResponse::Unauthorized().json("Unauthorized")),
//     }
// }

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

struct AppState {
    oauth: BasicClient,
    store: MemoryStore,
    verify: Mutex<Option<PkceCodeVerifier>>,
}

async fn login(data: web::Data<AppState>) -> HttpResponse {
    // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = &data
        .oauth
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the user's public repos and email.
        .add_scope(Scope::new("openid".to_string()))
        // This is imported to make it work
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    info!("Redirect to: {}: {}", authorize_url, csrf_state.secret());

    let mut veri = data.verify.lock().unwrap();

    *veri = Some(pkce_code_verifier);

    HttpResponse::Found()
        .append_header((header::LOCATION, authorize_url.to_string()))
        .finish()
}

//async fn index(session: Session, data: web::Data<AppStateWithCounter>, adata: web::Data<AppState>) -> HttpResponse {
async fn index(id: Identity, data: web::Data<AppStateWithCounter>) -> HttpResponse {
    let token = match id.identity() {
        None => {
            let html = format!(
                r#"<html>
                    <head><title>OAuth2 Test</title></head>
                    <body>
                        <p>You are not login, click <a href=/login>here to login</a></p>
                    </body>
                </html>"#
            );
            return HttpResponse::Ok().body(html);
        }
        Some(token) => token,
    };

    let mut counter = data.counter.lock().unwrap(); // <- get counter's MutexGuard
    *counter += 1; // <- access counter inside MutexGuard

    let html = format!(
        r#"<html>
                <head><title>OAuth2 Test</title></head>
                <body>
                <p>Logged in <a href=/logout>Logout</a></p>
                counter {} <br/>
                Hello {}
                </body>
            </html>"#,
        counter, token
    );

    HttpResponse::Ok().body(html)
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: Option<String>,
}

async fn auth(
    session: Identity,
    adata: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> HttpResponse {
    let code = AuthorizationCode::new(params.code.clone());
    let state = CsrfToken::new(params.state.clone());
    let _scope = params.scope.clone();

    let pkce_verifier = adata.verify.lock().unwrap().take().unwrap();

    // Exchange the code with a token.
    let token = adata
        .oauth
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier);

    info!("token: {:?}", token);

    let token_ret = token.request_async(async_http_client).await;

    info!("token_ret: {:?}", token_ret);

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            Kanidm returned the following state:
            <pre>{}</pre>
            Kanidm returned the following token:
            <pre>{:?}</pre>
        </body>
    </html>"#,
        state.secret(),
        //&token,
        token_ret
    );

    info!("{}", html);

    let access_token = match token_ret {
        Ok(token) => token.access_token().secret().to_owned(),
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    session.remember(access_token);

    HttpResponse::Found()
        .insert_header(("location", "/"))
        .finish()
}

async fn logout(id: Identity) -> HttpResponse {
    id.forget();
    HttpResponse::Found()
        .insert_header(("location", "/"))
        .finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let oauth2_settings = Config::builder()
        .add_source(config::File::with_name("oauth2.toml"))
        .add_source(config::Environment::with_prefix("OAUTH2"))
        .build()
        .unwrap();

    // Note: web::Data created _outside_ HttpServer::new closure
    let counter = web::Data::new(AppStateWithCounter {
        counter: Mutex::new(0),
    });

    // Is the `oauth2_rs_name`
    let kanidm_client_id = ClientId::new(oauth2_settings.get("client_id").unwrap());
    // Is the `oauth2_rs_basic_secret`
    let kanidm_client_secret = ClientSecret::new(oauth2_settings.get("client_secret").unwrap());
    let kanimd_auth_url = AuthUrl::new(oauth2_settings.get("auth_url").unwrap()).unwrap();
    let kanidm_token_url = TokenUrl::new(oauth2_settings.get("token_url").unwrap()).unwrap();

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
        RedirectUrl::new("http://localhost:18080/auth".to_string()).expect("Invalid redirect URL"),
    );

    let appstate = web::Data::new(AppState {
        oauth: client,
        verify: Mutex::new(None),
        store: MemoryStore::new(),
    });

    const COOKIENAME: &str = "COOKIEMAIL";

    // Generate a random 32 byte key. Note that it is important to use a unique
    // private key for every project. Anyone with access to the key can generate
    // authentication cookies for any user!
    let private_key: [u8; 32] = rand::thread_rng().gen();

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(counter.clone()) // <- register the created data
            .app_data(appstate.clone())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&private_key)
                    .name("MM-AUTH")
                    .secure(false),
            ))
            .wrap(middleware::Logger::default())
            .route("/", get().to(index))
            .route("/login", get().to(login))
            .route("/auth", get().to(auth))
            .route("/logout", get().to(logout))
    })
    .bind(("127.0.0.1", 18080))?
    .run()
    .await
}
