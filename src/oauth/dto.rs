use chrono::{DateTime, Utc};
use rocket::serde::{Deserialize, Serialize};
use crate::oauth::model::{OAuthApp, OAuthCredential, OAuthCredentialStatus};

// OAuth credential DTO

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthCredentialCreateRequestDTO {
    pub expire_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthCredentialCreateResponseDTO {
    pub id: i64,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub status: OAuthCredentialStatusDTO,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_at: Option<DateTime<Utc>>,
}

impl From<OAuthCredential> for OAuthCredentialCreateResponseDTO {
    fn from(oauth: OAuthCredential) -> Self {
        Self {
            id: oauth.id,
            client_id: oauth.client_id,
            client_secret: None,
            status: oauth.status.into(),
            expire_at: oauth.expire_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthCredentialUpdateRequestDTO {
    pub status: OAuthCredentialStatusDTO,
    pub expire_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthCredentialDTO {
    pub id: i64,
    pub client_id: String,
    pub status: OAuthCredentialStatusDTO,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<OAuthCredential> for OAuthCredentialDTO {
    fn from(oauth: OAuthCredential) -> Self {
        Self {
            id: oauth.id,
            client_id: oauth.client_id,
            status: oauth.status.into(),
            last_used: oauth.last_used,
            expire_at: oauth.expire_at,
            updated_at: oauth.updated_at,
            created_at: oauth.created_at,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub enum OAuthCredentialStatusDTO {
    ACTIVE,
    SUSPENDED,
    REVOKED,
    EXPIRED,
}

impl From<OAuthCredentialStatus> for OAuthCredentialStatusDTO {
    fn from(status: OAuthCredentialStatus) -> Self {
        match status {
            OAuthCredentialStatus::ACTIVE => Self::ACTIVE,
            OAuthCredentialStatus::SUSPENDED => Self::SUSPENDED,
            OAuthCredentialStatus::REVOKED => Self::REVOKED,
            OAuthCredentialStatus::EXPIRED => Self::EXPIRED,
        }
    }
}

impl From<OAuthCredentialStatusDTO> for OAuthCredentialStatus {
    fn from(status: OAuthCredentialStatusDTO) -> Self {
        match status {
            OAuthCredentialStatusDTO::ACTIVE => Self::ACTIVE,
            OAuthCredentialStatusDTO::SUSPENDED => Self::SUSPENDED,
            OAuthCredentialStatusDTO::REVOKED => Self::REVOKED,
            OAuthCredentialStatusDTO::EXPIRED => Self::EXPIRED,
        }
    }
}

// OAuth app DTO

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthAppCreateRequestDTO<'r> {
    pub redirect_uri: &'r str,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthAppCreateResponseDTO {
    pub id: i64,
    pub client_id: String,
    pub redirect_uri: String,
}

impl From<OAuthApp> for OAuthAppCreateResponseDTO {
    fn from(app: OAuthApp) -> Self {
        Self {
            id: app.id,
            client_id: app.client_id,
            redirect_uri: app.redirect_uri,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthAppUpdateRequestDTO<'r> {
    pub redirect_uri: &'r str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthAppDTO {
    pub id: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<OAuthApp> for OAuthAppDTO {
    fn from(app: OAuthApp) -> Self {
        Self {
            id: app.id,
            client_id: app.client_id,
            redirect_uri: app.redirect_uri,
            updated_at: app.updated_at,
            created_at: app.created_at,
        }
    }
}
