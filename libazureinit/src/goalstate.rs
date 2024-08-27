// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::{Client, StatusCode};

use std::time::Duration;

use serde::Deserialize;
use serde_xml_rs::from_str;

use tokio::time::timeout;

use crate::error::Error;
use crate::http;

#[derive(Debug, Deserialize, PartialEq)]
pub struct Goalstate {
    #[serde(rename = "Container")]
    container: Container,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Incarnation")]
    incarnation: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Container {
    #[serde(rename = "ContainerId")]
    container_id: String,
    #[serde(rename = "RoleInstanceList")]
    role_instance_list: RoleInstanceList,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct RoleInstanceList {
    #[serde(rename = "RoleInstance")]
    role_instance: RoleInstance,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct RoleInstance {
    #[serde(rename = "InstanceId")]
    instance_id: String,
}

const DEFAULT_GOALSTATE_URL: &str =
    "http://168.63.129.16/machine/?comp=goalstate";

pub async fn get_goalstate(
    client: &Client,
    retry_interval: Duration,
    total_timeout: Duration,
    url: Option<&str>,
) -> Result<Goalstate, Error> {
    let url = url.unwrap_or(DEFAULT_GOALSTATE_URL);

    let mut headers = HeaderMap::new();
    headers.insert("x-ms-agent-name", HeaderValue::from_static("azure-init"));
    headers.insert("x-ms-version", HeaderValue::from_static("2012-11-30"));

    let response = timeout(total_timeout, async {
        loop {
            let mut rest_timeout = total_timeout;

            if let Ok(response) = client
                .get(url)
                .headers(headers.clone())
                .timeout(Duration::from_secs(http::WIRESERVER_HTTP_TIMEOUT_SEC))
                .send()
                .await
            {
                let statuscode = response.status();

                if statuscode.is_success() && statuscode == StatusCode::OK {
                    tracing::info!("{}", format!("HTTP response succeeded with status {}", statuscode));
                    return Ok(response);
                }

                if !http::RETRY_CODES.contains(&statuscode) {
                    return response.error_for_status().map_err(|err| {
                        tracing::error!(error = ?err, "{}", format!("HTTP response failed immediately due to status {}", statuscode));
                        err
                    });
                }
            }

            rest_timeout = rest_timeout.saturating_sub(Duration::from_secs(http::IMDS_HTTP_TIMEOUT_SEC));
            tracing::info!("{}", format!("Retrying to get HTTP response in {} sec, remaining timeout {} sec.", retry_interval.as_secs(), rest_timeout.as_secs()));

            tokio::time::sleep(retry_interval).await;
        }
    })
    .await?;

    let goalstate_body = response?.text().await?;

    let goalstate: Goalstate = from_str(&goalstate_body)?;

    Ok(goalstate)
}

const DEFAULT_HEALTH_URL: &str = "http://168.63.129.16/machine/?comp=health";

pub async fn report_health(
    client: &Client,
    goalstate: Goalstate,
    retry_interval: Duration,
    total_timeout: Duration,
    url: Option<&str>,
) -> Result<(), Error> {
    let url = url.unwrap_or(DEFAULT_HEALTH_URL);

    let mut headers = HeaderMap::new();
    headers.insert("x-ms-agent-name", HeaderValue::from_static("azure-init"));
    headers.insert("x-ms-version", HeaderValue::from_static("2012-11-30"));
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("text/xml;charset=utf-8"),
    );

    let post_request = build_report_health_file(goalstate);

    _ = timeout(total_timeout, async {
        loop {
            let mut rest_timeout = total_timeout;

            if let Ok(response) = client
                .post(url)
                .headers(headers.clone())
                .body(post_request.clone())
                .timeout(Duration::from_secs(http::WIRESERVER_HTTP_TIMEOUT_SEC))
                .send()
                .await
            {
                let statuscode = response.status();

                if statuscode.is_success() && statuscode == StatusCode::OK {
                    tracing::info!("{}", format!("HTTP response succeeded with status {}", statuscode));
                    return Ok(response);
                }

                if !http::RETRY_CODES.contains(&statuscode) {
                    return response.error_for_status().map_err(|err| {
                        tracing::error!(error = ?err, "{}", format!("HTTP response failed immediately due to status {}", statuscode));
                        err
                    });
                }
            }

            rest_timeout = rest_timeout.saturating_sub(Duration::from_secs(http::IMDS_HTTP_TIMEOUT_SEC));
            tracing::info!("{}", format!("Retrying to get HTTP response in {} sec, remaining timeout {} sec.", retry_interval.as_secs(), rest_timeout.as_secs()));

            tokio::time::sleep(retry_interval).await;
        }
    })
    .await?;

    Ok(())
}

fn build_report_health_file(goalstate: Goalstate) -> String {
    let post_request =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
    <Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n\
        <GoalStateIncarnation>$GOAL_STATE_INCARNATION</GoalStateIncarnation>\n\
        <Container>\n\
            <ContainerId>$CONTAINER_ID</ContainerId>\n\
            <RoleInstanceList>\n\
                <Role>\n\
                    <InstanceId>$INSTANCE_ID</InstanceId>\n\
                    <Health>\n\
                        <State>Ready</State>\n\
                    </Health>\n\
                </Role>\n\
            </RoleInstanceList>\n\
        </Container>\n\
    </Health>";

    let post_request =
        post_request.replace("$GOAL_STATE_INCARNATION", &goalstate.incarnation);
    let post_request = post_request
        .replace("$CONTAINER_ID", &goalstate.container.container_id);
    post_request.replace(
        "$INSTANCE_ID",
        &goalstate
            .container
            .role_instance_list
            .role_instance
            .instance_id,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_report_health_file, get_goalstate, report_health, Goalstate,
    };

    use reqwest::{header, Client, StatusCode};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::time;

    use crate::http;

    static GOALSTATE_STR: &str = "<Goalstate>
            <Container>
                <ContainerId>2</ContainerId>
                <RoleInstanceList>
                    <RoleInstance>
                        <InstanceId>test_user_instance_id</InstanceId>
                    </RoleInstance>
                </RoleInstanceList>
            </Container>
            <Version>example_version</Version>
            <Incarnation>test_goal_incarnation</Incarnation>
        </Goalstate>";

    static HEALTH_STR: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
        <Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n\
            <GoalStateIncarnation>test_goal_incarnation</GoalStateIncarnation>\n\
            <Container>\n\
                <ContainerId>2</ContainerId>\n\
                <RoleInstanceList>\n\
                    <Role>\n\
                        <InstanceId>test_user_instance_id</InstanceId>\n\
                        <Health>\n\
                            <State>Ready</State>\n\
                        </Health>\n\
                    </Role>\n\
                </RoleInstanceList>\n\
            </Container>\n\
        </Health>";
    #[test]
    fn test_parsing_goalstate() {
        let goalstate: Goalstate = serde_xml_rs::from_str(GOALSTATE_STR)
            .expect("Failed to parse the goalstate XML.");
        assert_eq!(goalstate.container.container_id, "2".to_owned());
        assert_eq!(
            goalstate
                .container
                .role_instance_list
                .role_instance
                .instance_id,
            "test_user_instance_id".to_owned()
        );
        assert_eq!(goalstate.version, "example_version".to_owned());
        assert_eq!(goalstate.incarnation, "test_goal_incarnation".to_owned());
    }

    #[tokio::test]
    async fn test_build_report_health_file() {
        let goalstate: Goalstate = serde_xml_rs::from_str(GOALSTATE_STR)
            .expect("Failed to parse the goalstate XML.");

        let actual_output = build_report_health_file(goalstate);
        assert_eq!(actual_output, HEALTH_STR);
    }

    // Returns expected HTTP response for the given status code and body string.
    async fn get_http_response_payload(
        statuscode: &StatusCode,
        body_str: &str,
    ) -> String {
        // Reply message includes the whole body in case of OK, otherwise empty data.
        let res = match statuscode {
            &StatusCode::OK => format!("HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", statuscode.as_u16(), statuscode.to_string(), body_str.len(), body_str.to_string()),
            _ => {
                format!("HTTP/1.1 {} {}\r\n\r\n", statuscode.as_u16(), statuscode.to_string())
            }
        };

        res
    }

    // Runs a test around sending via get_goalstate() with a given statuscode.
    async fn run_goalstate_retry(statuscode: &StatusCode) -> bool {
        const HTTP_TOTAL_TIMEOUT_SEC: u64 = 5 * 60;
        const HTTP_PERCLIENT_TIMEOUT_SEC: u64 = 30;
        const HTTP_RETRY_INTERVAL_SEC: u64 = 2;

        let mut default_headers = header::HeaderMap::new();
        let user_agent =
            header::HeaderValue::from_str("azure-init test").unwrap();

        // Run local test servers for goalstate and health that reply with simple test data.
        let gs_ok_payload =
            get_http_response_payload(statuscode, GOALSTATE_STR).await;
        let gs_serverlistener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gs_addr = gs_serverlistener.local_addr().unwrap();

        let health_ok_payload =
            get_http_response_payload(statuscode, HEALTH_STR).await;
        let health_serverlistener =
            TcpListener::bind("127.0.0.1:0").await.unwrap();
        let health_addr = health_serverlistener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut serverstream, _) =
                gs_serverlistener.accept().await.unwrap();
            serverstream
                .write_all(gs_ok_payload.as_bytes())
                .await
                .unwrap();

            let (mut serverstream, _) =
                health_serverlistener.accept().await.unwrap();
            serverstream
                .write_all(health_ok_payload.as_bytes())
                .await
                .unwrap();
        });

        // Advance time to 5 minutes later, to prevent tests from being blocked
        // for long time when retrying on RETRY_CODES.
        time::pause();
        time::advance(Duration::from_secs(HTTP_TOTAL_TIMEOUT_SEC)).await;

        default_headers.insert(header::USER_AGENT, user_agent);
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_PERCLIENT_TIMEOUT_SEC))
            .default_headers(default_headers)
            .build()
            .unwrap();

        let vm_goalstate = get_goalstate(
            &client,
            Duration::from_secs(HTTP_RETRY_INTERVAL_SEC),
            Duration::from_secs(HTTP_TOTAL_TIMEOUT_SEC),
            Some(
                format!("http://{:}:{:}/", gs_addr.ip(), gs_addr.port())
                    .as_str(),
            ),
        )
        .await;

        if !vm_goalstate.is_ok() {
            time::resume();
            return false;
        }

        let res_health = report_health(
            &client,
            vm_goalstate.unwrap(),
            Duration::from_secs(HTTP_RETRY_INTERVAL_SEC),
            Duration::from_secs(HTTP_TOTAL_TIMEOUT_SEC),
            Some(
                format!(
                    "http://{:}:{:}/",
                    health_addr.ip(),
                    health_addr.port()
                )
                .as_str(),
            ),
        )
        .await;

        time::resume();

        res_health.is_ok()
    }

    #[tokio::test]
    async fn goalstate_query_retry() {
        // status codes that should succeed.
        assert!(run_goalstate_retry(&StatusCode::OK).await);

        // status codes that should be retried up to 5 minutes.
        for rc in http::RETRY_CODES {
            assert!(!run_goalstate_retry(rc).await);
        }

        // status codes that should result into immediate failures.
        for rc in http::HARDFAIL_CODES {
            assert!(!run_goalstate_retry(rc).await);
        }
    }
}
