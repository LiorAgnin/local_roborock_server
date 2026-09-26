//! RemoteOnboardingApi against a mock admin server over plain HTTP.

mod support;

use roborock_onboard::api::{ApiError, OnboardingApi, RemoteOnboardingApi};
use serde_json::json;
use support::{MockAdmin, Reply};

fn with_session_cookie(reply: Reply) -> Reply {
    Reply {
        set_cookie: Some("admin_session=abc123; Path=/; HttpOnly".into()),
        ..reply
    }
}

#[test]
fn login_posts_password_and_later_requests_carry_the_session_cookie() {
    let admin = MockAdmin::start(|req| match req.path.as_str() {
        "/admin/api/login" => with_session_cookie(Reply::json(200, json!({"ok": true}))),
        _ => Reply::json(200, json!({"devices": [{"duid": "d1"}]})),
    });
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);

    api.login().unwrap();
    let devices = api.list_devices().unwrap();

    assert_eq!(devices, vec![json!({"duid": "d1"})]);
    let requests = admin.requests();
    assert_eq!(
        admin.paths(),
        vec!["POST /admin/api/login", "GET /admin/api/onboarding/devices"]
    );
    assert_eq!(requests[0].body, r#"{"password":"secret"}"#);
    assert_eq!(
        requests[0].content_type.as_deref(),
        Some("application/json")
    );
    assert_eq!(requests[1].cookie.as_deref(), Some("admin_session=abc123"));
}

#[test]
fn cookie_jar_keeps_latest_value_per_name_and_honours_max_age_zero() {
    let admin = MockAdmin::start(|req| match req.path.as_str() {
        "/admin/api/login" => Reply {
            set_cookie: Some("a=1; Path=/".into()),
            ..Reply::json(200, json!({}))
        },
        "/admin/api/status" => Reply {
            set_cookie: Some("b=2; HttpOnly".into()),
            ..Reply::json(200, json!({}))
        },
        "/admin/api/onboarding/devices" => Reply {
            set_cookie: Some("a=3".into()),
            ..Reply::json(200, json!({}))
        },
        "/admin/api/onboarding/sessions" => Reply {
            set_cookie: Some("b=; Max-Age=0".into()),
            ..Reply::json(200, json!({}))
        },
        _ => Reply::json(200, json!({})),
    });
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);
    api.login().unwrap();
    api.get_status().unwrap();
    api.list_devices().unwrap();
    api.start_session("d").unwrap();
    api.get_session("s").unwrap();

    let cookies: Vec<Option<String>> = admin.requests().into_iter().map(|r| r.cookie).collect();
    assert_eq!(
        cookies,
        vec![
            None,
            Some("a=1".into()),
            Some("a=1; b=2".into()),
            Some("a=3; b=2".into()),
            Some("a=3".into()),
        ]
    );
}

#[test]
fn login_is_only_sent_once() {
    let admin = MockAdmin::start(|_| Reply::json(200, json!({})));
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);
    api.login().unwrap();
    api.login().unwrap();
    assert_eq!(admin.paths(), vec!["POST /admin/api/login"]);
}

#[test]
fn login_401_means_invalid_password() {
    let admin = MockAdmin::start(|_| Reply::json(401, json!({"error": "nope"})));
    let api = RemoteOnboardingApi::new(&admin.base_url, "wrong", false);
    assert_eq!(
        api.login(),
        Err(ApiError::Failed("Invalid admin password.".into()))
    );
    // Not marked as logged in after a failure.
    let _ = api.login();
    assert_eq!(admin.paths().len(), 2);
}

#[test]
fn non_login_401_is_reported_as_http_error() {
    let admin = MockAdmin::start(|_| Reply::json(401, json!({"error": "Unauthorized"})));
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);
    assert_eq!(
        api.get_status(),
        Err(ApiError::Failed("HTTP 401: Unauthorized".into()))
    );
}

#[test]
fn session_endpoints_use_expected_methods_and_quoted_ids() {
    let admin = MockAdmin::start(|req| match req.method.as_str() {
        "POST" => Reply::json(200, json!({"session_id": "s/1"})),
        "DELETE" => Reply::json(200, json!({"ok": true})),
        _ => Reply::json(200, json!({"query_samples": 1})),
    });
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);

    let session = api.start_session("duid-1").unwrap();
    assert_eq!(session["session_id"], json!("s/1"));
    assert_eq!(api.get_session("s/1").unwrap()["query_samples"], json!(1));
    assert_eq!(api.delete_session("s/1").unwrap()["ok"], json!(true));

    assert_eq!(
        admin.paths(),
        vec![
            "POST /admin/api/onboarding/sessions",
            "GET /admin/api/onboarding/sessions/s%2F1",
            "DELETE /admin/api/onboarding/sessions/s%2F1",
        ]
    );
    assert_eq!(admin.requests()[0].body, r#"{"duid":"duid-1"}"#);
}

#[test]
fn empty_body_is_an_empty_object() {
    let admin = MockAdmin::start(|_| Reply::raw(200, ""));
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);
    assert!(api.get_status().unwrap().is_empty());
}

#[test]
fn devices_missing_or_not_a_list_is_empty() {
    let admin = MockAdmin::start(|_| Reply::json(200, json!({"devices": "nope"})));
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);
    assert!(api.list_devices().unwrap().is_empty());
}

#[test]
fn invalid_json_and_non_object_responses_fail() {
    let admin = MockAdmin::start(|req| match req.path.as_str() {
        "/admin/api/status" => Reply::raw(200, "<html>oops</html>"),
        _ => Reply::raw(200, "[1, 2]"),
    });
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);
    assert_eq!(
        api.get_status(),
        Err(ApiError::Failed(
            "Invalid JSON response from /admin/api/status: <html>oops</html>".into()
        ))
    );
    assert_eq!(
        api.get_session("x"),
        Err(ApiError::Failed(
            "Unexpected response from /admin/api/onboarding/sessions/x: [1,2]".into()
        ))
    );
}

#[test]
fn server_errors_use_formatted_message() {
    let admin = MockAdmin::start(|_| Reply::json(409, json!({"detail": "session busy"})));
    let api = RemoteOnboardingApi::new(&admin.base_url, "secret", false);
    assert_eq!(
        api.start_session("d"),
        Err(ApiError::Failed("HTTP 409: session busy".into()))
    );
}

#[test]
fn connection_refused_is_unreachable() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let base = format!("http://127.0.0.1:{port}");
    let api = RemoteOnboardingApi::new(&base, "secret", false);
    match api.get_status() {
        Err(ApiError::Unreachable(msg)) => {
            assert!(
                msg.starts_with(&format!("Unable to reach {base}: ")),
                "{msg}"
            )
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
}

#[test]
fn trailing_slash_in_base_url_is_ignored() {
    let admin = MockAdmin::start(|_| Reply::json(200, json!({})));
    let api = RemoteOnboardingApi::new(&format!("{}/", admin.base_url), "secret", false);
    api.get_status().unwrap();
    assert_eq!(admin.paths(), vec!["GET /admin/api/status"]);
}
