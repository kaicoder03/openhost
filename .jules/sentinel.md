## 2025-05-15 - Strict HTTP Head Validation
**Vulnerability:** Memory exhaustion DoS and potential HTTP request smuggling.
**Learning:** The hand-rolled HTTP parser was vulnerable to memory exhaustion because it didn't cap the `REQUEST_HEAD` size before processing. It also lacked strict RFC 7230 compliance, specifically failing to reject whitespace before colons and bare line terminators, which can be exploited for request smuggling.
**Prevention:** Always enforce explicit size limits on inbound protocol frames and strictly validate delimiters (like `:` and `\r\n`) to ensure they exactly match the expected protocol grammar without prohibited optional whitespace.
