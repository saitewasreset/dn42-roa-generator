use std::env;
use std::path::Path;
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::routing::get;
use tracing::info;
use dn42_roa_generator::{AppConfig, AppState, ROACache};
use dn42_roa_generator::io::background_updater;

const CONFIG_PATH: &str = "config.json";

fn init_default_config() -> anyhow::Result<()> {
    let default_config = AppConfig::default();

    let config_json = serde_json::to_string_pretty(&default_config)?;

    std::fs::write(CONFIG_PATH, config_json)?;

    info!("Wrote default configuration to {}", CONFIG_PATH);

    Ok(())
}

fn init_app_state() -> AppState {
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| CONFIG_PATH.to_string());

    let config_path = Path::new(config_path.as_str());

    let app_config = if config_path.exists() {
        serde_json::from_reader(std::fs::File::open(config_path).unwrap())
            .map(|config| {
                info!("Loaded configuration from {:?}", config_path);

                config
            })
            .unwrap_or_else(|e| {
                panic!("Failed to load configuration from {:?}: {:?}", config_path, e);
            })
    } else {
        info!("Configuration file {:?} does not exist. Using default configuration.", config_path);

        if let Err(e) = init_default_config() {
            panic!("Failed to write default configuration to {:?}: {:?}", config_path, e);
        }

        AppConfig::default()
    };

    AppState {
        config: std::sync::Arc::new(app_config),
        data: std::sync::Arc::new(std::sync::RwLock::new(ROACache::default())),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let app_state = init_app_state();

    let update_task_app_state = app_state.clone();

    tokio::spawn(async move {background_updater(update_task_app_state).await;});

    let app = Router::new()
        .route(&app_state.config.roa_endpoint, get(get_roa_json))
        .with_state(app_state.clone());

    let listener = tokio::net::TcpListener::bind(&app_state.config.listen_address).await?;

    info!("Listening on: {}", &app_state.config.listen_address);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_roa_json(State(state): State<AppState>) -> Response<Body> {
    let data = match state.data.read() {
        Ok(data) => data,
        Err(_) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    (
        [("Content-Type", "application/json")],
        data.json_content.clone(),
    ).into_response()
}