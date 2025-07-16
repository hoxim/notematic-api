use actix_web::{dev::{ServiceRequest, ServiceResponse}, Error, HttpResponse};
use actix_service::{Service, Transform};
use futures::future::{ok, Ready};
use futures::Future;
use std::pin::Pin;
use log::{info, warn, debug};

use crate::utils::verify_jwt;

/// Middleware for admin-only endpoints
pub struct AdminRoleMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for AdminRoleMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let headers = req.headers();
        let peer_addr = req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        debug!("AdminRoleMiddleware processing request from IP: {}", peer_addr);
        if let Some(auth_header) = headers.get("Authorization") {
            if let Ok(auth_value) = auth_header.to_str() {
                if auth_value.starts_with("Bearer ") {
                    let token = &auth_value[7..];
                    match verify_jwt(token) {
                        Ok(claims) => {
                            if claims.token_type == "access" && claims.role == "admin" {
                                info!("Valid admin JWT token for user: {} from IP: {}", claims.sub, peer_addr);
                                let fut = self.service.call(req);
                                return Box::pin(async move { fut.await });
                            } else {
                                warn!("User {} does not have admin role", claims.sub);
                                let (req, _) = req.into_parts();
                                let response = HttpResponse::Forbidden().json(serde_json::json!({
                                    "error": "Admin role required"
                                }));
                                return Box::pin(async move { Ok(ServiceResponse::new(req, response)) });
                            }
                        }
                        Err(_) => {
                            warn!("Invalid JWT token from IP: {}", peer_addr);
                            let (req, _) = req.into_parts();
                            let response = HttpResponse::Unauthorized().json(serde_json::json!({
                                "error": "Invalid token"
                            }));
                            return Box::pin(async move { Ok(ServiceResponse::new(req, response)) });
                        }
                    }
                }
            }
        }
        warn!("Missing or invalid Authorization header from IP: {}", peer_addr);
        let (req, _) = req.into_parts();
        let response = HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Missing or invalid Authorization header"
        }));
        Box::pin(async move { Ok(ServiceResponse::new(req, response)) })
    }
}

pub struct AdminRoleMiddlewareFactory;

impl<S> Transform<S, ServiceRequest> for AdminRoleMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Transform = AdminRoleMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AdminRoleMiddleware { service })
    }
}

pub struct JwtMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for JwtMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let headers = req.headers();
        let peer_addr = req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        debug!("JWT middleware processing request from IP: {}", peer_addr);
        
        if let Some(auth_header) = headers.get("Authorization") {
            if let Ok(auth_value) = auth_header.to_str() {
                // Sprawdź format "Bearer <token>"
                if auth_value.starts_with("Bearer ") {
                    let token = &auth_value[7..]; // Usuń "Bearer "
                    debug!("Processing JWT token from IP: {}", peer_addr);
                    
                    match verify_jwt(token) {
                        Ok(claims) => {
                            // Sprawdź czy to access token
                            if claims.token_type == "access" {
                                // Token poprawny, kontynuuj obsługę
                                info!("Valid JWT token for user: {} from IP: {}", claims.sub, peer_addr);
                                let fut = self.service.call(req);
                                return Box::pin(async move { fut.await });
                            } else {
                                // To nie jest access token
                                warn!("Invalid token type for IP: {}", peer_addr);
                                let (req, _) = req.into_parts();
                                let response = HttpResponse::Unauthorized().json(serde_json::json!({
                                    "error": "Invalid token type"
                                }));
                                return Box::pin(async move { Ok(ServiceResponse::new(req, response)) });
                            }
                        }
                        Err(_) => {
                            // Token niepoprawny
                            warn!("Invalid JWT token from IP: {}", peer_addr);
                            let (req, _) = req.into_parts();
                            let response = HttpResponse::Unauthorized().json(serde_json::json!({
                                "error": "Invalid token"
                            }));
                            return Box::pin(async move { Ok(ServiceResponse::new(req, response)) });
                        }
                    }
                }
            }
        }

        // Brak nagłówka Authorization lub niepoprawny format
        warn!("Missing or invalid Authorization header from IP: {}", peer_addr);

        // Brak nagłówka Authorization lub niepoprawny format
        let (req, _) = req.into_parts();
        let response = HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Missing or invalid Authorization header"
        }));
        Box::pin(async move { Ok(ServiceResponse::new(req, response)) })
    }
}

pub struct JwtMiddlewareFactory;

impl<S> Transform<S, ServiceRequest> for JwtMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Transform = JwtMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddleware { service })
    }
}