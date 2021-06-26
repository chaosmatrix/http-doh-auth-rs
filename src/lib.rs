use std::collections::HashMap;
use std::time::Duration;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(UpstreamCallConfigRoot::new())
    });
}

#[derive(Debug, Default)]
struct UpstreamCall {
    doh_cluster_name: String,
    timeout_second: u64,
    log_sub_request: bool,
    doh: DohConfig,
}

impl UpstreamCall {
    fn new() -> Self {
        return Self {
            doh_cluster_name: String::new(),
            timeout_second: 30,
            log_sub_request: false,
            ..Default::default()
        };
    }

    // 1. fix hit return
    // 2. default allow
    // 3. same order, allow has high priority
    fn match_rules(&self, ptr: &str) -> bool {
        for _rule in self.doh.rules.iter() {
            let regex_str = if !_rule.regx_allow.is_empty() {
                _rule.regx_allow.as_str()
            } else {
                _rule.regx_deny.as_str()
            };
            if !regex_str.is_empty() {
                let _re = Regex::new(regex_str).unwrap();
                return _re.is_match(ptr);
            }
        }
        true
    }
}

impl HttpContext for UpstreamCall {
    fn on_http_request_headers(&mut self, _num_headers: usize) -> Action {
        let mut _client_ip = "";
        let _client_ip_header = if self.doh.client_ip_header.is_empty() {
            "x-forwarded-for"
        } else {
            self.doh.client_ip_header.as_str()
        };
        let _headers = self.get_http_request_headers();
        for _i in 0.._headers.len() {
            proxy_wasm::hostcalls::log(
                LogLevel::Debug,
                format!("header: '{:?} = {:?}'", _headers[_i].0, _headers[_i].1).as_str(),
            );
            if _headers[_i].0 == _client_ip_header {
                _client_ip = _headers[_i].1.as_str();
                //break;
            }
        }

        // https://dns.google.com/query?name=8.8.8.8.in-addr.arpa&rr_type=PTR&ecs=
        let mut doh_uri = String::new();
        doh_uri.push_str("/resolve?name=");
        doh_uri.push_str(ipv42arpa(_client_ip).as_str());
        doh_uri.push_str("&type=PTR");
        proxy_wasm::hostcalls::log(
            LogLevel::Debug,
            format!(
                "doh_uri: '{:?}', client_ip: '{:?}'",
                doh_uri.as_str(),
                _client_ip
            )
            .as_str(),
        );

        let mut headers = Vec::<(&str, &str)>::new();
        headers.push((":method", "GET"));
        headers.push((":path", doh_uri.as_str()));
        //headers.push((":scheme", "http"));
        //headers.push((":authority", "dns.google"));
        headers.push((":authority", self.doh.host.as_str()));

        let x = self.dispatch_http_call(
            self.doh_cluster_name.as_str(),
            headers,
            None,
            vec![],
            Duration::from_secs(self.timeout_second),
        );
        if self.log_sub_request {
            proxy_wasm::hostcalls::log(LogLevel::Info, format!("response: {:?}", x).as_str());
        }
        Action::Pause
    }

    fn on_http_response_headers(&mut self, _num_headers: usize) -> Action {
        Action::Continue
    }
}

impl Context for UpstreamCall {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        _body_size: usize,
        _num_trailers: usize,
    ) {
        let mut _content_length: usize = 1000;
        for (k, v) in self.get_http_call_response_headers() {
            if k == ":status" {
                if self.log_sub_request {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        format!(
                            "HTTP Call response status : {:?}, authorized: {:?}",
                            v,
                            v.starts_with("2")
                        )
                        .as_str(),
                    );
                }
                /*
                if v.starts_with("2") {
                    self.resume_http_request();
                    return;
                }
                */
            } else if k == "content-length" {
                _content_length = v.parse::<usize>().unwrap();
            }
        }
        match self.get_http_call_response_body(0, _content_length) {
            Some(_resp) => {
                let doh_response: DohResponse =
                    serde_json::from_str(String::from_utf8(_resp).unwrap().as_str()).unwrap();
                let _ptr = doh_response.get_ptr_record_domain();
                proxy_wasm::hostcalls::log(
                    LogLevel::Info,
                    format!("HTTP Call response doh_domain : {:?}", _ptr,).as_str(),
                );
                if self.match_rules(_ptr) {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        format!("allow ptr : {:?}", _ptr,).as_str(),
                    );
                    self.resume_http_request();
                    return;
                }
            }
            None => {}
        }
        self.resume_http_request();
        //return;
        self.send_http_response(403, vec![], Some(b"Access forbidden.\r\n"));
    }
}
impl RootContext for UpstreamCall {}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default)]
struct UpstreamCallConfigRoot {
    doh_cluster_name: String,
    timeout_second: u64,
    log_sub_request: bool,
    doh: DohConfig,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default)]
#[derive(Default)]
struct DohConfig {
    //uri: String,
    //headers: HashMap<String, String>,
    host: String,
    client_ip_header: String,
    rules: Vec<RuleConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default)]
#[derive(Default)]
struct RuleConfig {
    regx_allow: String,
    regx_deny: String,
}

impl Default for UpstreamCallConfigRoot {
    fn default() -> Self {
        UpstreamCallConfigRoot {
            doh_cluster_name: String::new(),
            timeout_second: 30,
            log_sub_request: false,
            doh: DohConfig {
                host: String::new(),
                client_ip_header: "x-forwarded-for".to_string(),
                rules: Vec::new(),
            },
        }
    }
}

impl UpstreamCallConfigRoot {
    fn new() -> Self {
        return Self {
            ..Default::default()
        };
    }
}

impl Context for UpstreamCallConfigRoot {}

impl RootContext for UpstreamCallConfigRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_configuration() {
            let config_string = String::from_utf8(config_bytes).unwrap();
            let uccr: UpstreamCallConfigRoot =
                serde_json::from_str(config_string.as_str()).unwrap();
            if uccr.doh_cluster_name.is_empty() {
                // FIXME: verify cluster_name exist on config or not
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    format!(
                        "invalid config: '{:?}', 'doh_cluster_name: {:?}' not a valid cluster name",
                        config_string.as_str(),
                        uccr.doh_cluster_name.as_str(),
                    )
                    .as_str(),
                );
                return false;
            }
            self.doh_cluster_name = uccr.doh_cluster_name;
            self.timeout_second = uccr.timeout_second;
            self.log_sub_request = uccr.log_sub_request;
            self.doh = uccr.doh.clone();
        }
        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            format!("parse configuration file success.",).as_str(),
        );
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(UpstreamCall {
            doh_cluster_name: self.doh_cluster_name.clone(),
            timeout_second: self.timeout_second,
            log_sub_request: self.log_sub_request,
            doh: self.doh.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

/*
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "8.8.8.8.in-addr.arpa.",
      "type": 12
    }
  ],
  "Answer": [
    {
      "name": "8.8.8.8.in-addr.arpa.",
      "type": 12,UpstreamCall
      "TTL": 19968,
      "data": "dns.google."
    }
  ]
}
*/
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default)]
#[derive(Default)]
struct DohResponse {
    Status: u16,
    #[serde(rename = "TC")]
    Tc: bool,
    #[serde(rename = "RD")]
    Rd: bool,
    #[serde(rename = "AD")]
    Ad: bool,
    #[serde(rename = "Cd")]
    Cd: bool,
    Question: Vec<DohQuestion>,
    Answer: Vec<DohAnswer>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default)]
#[derive(Default)]
struct DohQuestion {
    #[serde(rename = "name")]
    Name: String,
    #[serde(rename = "type")]
    Type: u16,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default)]
#[derive(Default)]
struct DohAnswer {
    #[serde(rename = "name")]
    Name: String,
    #[serde(rename = "type")]
    Type: u16,
    #[serde(rename = "TTL")]
    Ttl: u32,
    #[serde(rename = "data")]
    Data: String,
}

impl DohResponse {
    // PTR as FQDN
    fn get_ptr_record(&self) -> &str {
        if self.Status == 0 && self.Answer.len() > 0 {
            // ? verify name && ttl
            return self.Answer[0].Data.as_str();
        }
        ""
    }

    fn get_ptr_record_domain(&self) -> &str {
        self.get_ptr_record().trim_end_matches(|x| x == '.')
    }
}

fn ipv42arpa(addr: &str) -> String {
    // .in-addr.arpa.
    let mut _arpa = String::new();
    let ips: Vec<&str> = addr.split(',').next().unwrap().split('.').collect();
    for v in ips.iter().rev() {
        _arpa.push_str(v);
        _arpa.push('.');
    }
    _arpa.push_str("in-addr.arpa.");
    _arpa
}

mod tests {
    #[test]
    fn it_works() {
        assert_eq!(1, 1);
    }
}
