package com.sqlihunter.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scope.Scope;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Scope enforcement tests. Montoya interfaces are stubbed with dynamic proxies
 * so only the handful of methods ScopeController uses need behaviour.
 */
class ScopeControllerTest {

    private HttpRequest request(String host, String path, String url) {
        HttpService svc = (HttpService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class[]{HttpService.class},
                (p, m, a) -> "host".equals(m.getName()) ? host : def(m));
        return (HttpRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class[]{HttpRequest.class},
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "httpService": return svc;
                        case "pathWithoutQuery": return path;
                        case "url": return url;
                        default: return def(m);
                    }
                });
    }

    private MontoyaApi api(boolean inBurpScope) {
        Scope scope = (Scope) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class[]{Scope.class},
                (p, m, a) -> "isInScope".equals(m.getName()) ? inBurpScope : def(m));
        return (MontoyaApi) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class[]{MontoyaApi.class},
                (p, m, a) -> "scope".equals(m.getName()) ? scope : def(m));
    }

    private static Object def(java.lang.reflect.Method m) {
        Class<?> r = m.getReturnType();
        if (r == boolean.class) return false;
        if (r == int.class) return 0;
        if (r == long.class) return 0L;
        if (r == short.class) return (short) 0;
        return null;
    }

    @Test
    void emptyAllowListBlocksEverything() {
        ScanConfig c = new ScanConfig();
        ScopeController sc = new ScopeController(c, api(true));
        assertNotNull(sc.rejectionReason(request("app.example.com", "/x", "https://app.example.com/x")));
    }

    @Test
    void hostNotInAllowListBlocked() {
        ScanConfig c = new ScanConfig();
        c.inScopeHosts().add("app.example.com");
        ScopeController sc = new ScopeController(c, api(true));
        assertNotNull(sc.rejectionReason(request("evil.test", "/x", "https://evil.test/x")));
    }

    @Test
    void excludedPathBlocked() {
        ScanConfig c = new ScanConfig();
        c.inScopeHosts().add("app.example.com");
        ScopeController sc = new ScopeController(c, api(true));
        assertNotNull(sc.rejectionReason(
                request("app.example.com", "/account/logout", "https://app.example.com/account/logout")));
    }

    @Test
    void wildcardHostAllowedWhenInBurpScope() {
        ScanConfig c = new ScanConfig();
        c.inScopeHosts().add("*.example.com");
        ScopeController sc = new ScopeController(c, api(true));
        assertNull(sc.rejectionReason(
                request("api.example.com", "/search", "https://api.example.com/search")));
    }

    @Test
    void allowedHostOutsideBurpScopeIsStillAllowed() {
        // SQLiHunter's own allow-list is authoritative; Burp scope is advisory.
        ScanConfig c = new ScanConfig();
        c.inScopeHosts().add("app.example.com");
        ScopeController sc = new ScopeController(c, api(false));
        var req = request("app.example.com", "/search", "https://app.example.com/search");
        assertNull(sc.rejectionReason(req), "own allow-list should authorise regardless of Burp scope");
        assertFalse(sc.inBurpScope(req), "but Burp scope is reported as advisory false");
    }

    @Test
    void isAllowedMirrorsRejectionReason() {
        ScanConfig c = new ScanConfig();
        c.inScopeHosts().add("app.example.com");
        ScopeController sc = new ScopeController(c, api(true));
        HttpRequest ok = request("app.example.com", "/search", "https://app.example.com/search");
        assertTrue(sc.isAllowed(ok));
        assertFalse(sc.isAllowed(request("other.test", "/x", "https://other.test/x")));
    }
}
