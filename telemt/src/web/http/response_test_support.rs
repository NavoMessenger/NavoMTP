/// Splits one complete raw HTTP response into head and body slices.
pub(in crate::web::http) fn split_response(response: &[u8]) -> (&[u8], &[u8]) {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    (&response[..separator], &response[separator + 4..])
}

/// Returns one case-insensitive header value from a raw HTTP response head.
pub(in crate::web::http) fn response_header<'a>(headers: &'a [u8], name: &str) -> &'a str {
    std::str::from_utf8(headers)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(header, value)| header.eq_ignore_ascii_case(name).then_some(value.trim()))
        .unwrap()
}
