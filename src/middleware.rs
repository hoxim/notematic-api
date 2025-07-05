use actix_web::{dev::{ServiceRequest, ServiceResponse}, Error, HttpResponse};
use actix_service::{Service, Transform};
use futures::future::{ok, Ready};
use futures::Future;
use std::pin::Pin;

use crate::utils::verify_jwt;

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
        if let Some(auth_header) = headers.get("Authorization") {
            if let Ok(token) = auth_header.to_str() {
                match verify_jwt(token) {
                    Ok(_) => {
                        // Token poprawny, kontynuuj obsługę
                        let fut = self.service.call(req);
                        return Box::pin(async move { fut.await });
                    }
                    Err(_) => {
                        // Token niepoprawny
                        let (req, _) = req.into_parts();
                        let response = HttpResponse::Unauthorized().finish();
                        return Box::pin(async move { Ok(ServiceResponse::new(req, response)) });
                    }
                }
            }
        }

        // Brak nagłówka Authorization
        let (req, _) = req.into_parts();
        let response = HttpResponse::Unauthorized().finish();
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