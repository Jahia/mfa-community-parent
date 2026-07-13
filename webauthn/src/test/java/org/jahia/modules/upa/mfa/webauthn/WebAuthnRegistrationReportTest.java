package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeIteratorWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.JCRWorkspaceWrapper;
import org.jahia.services.content.QueryManagerWrapper;
import org.jahia.services.query.QueryResultWrapper;
import org.jahia.services.query.QueryWrapper;
import org.junit.Test;
import org.mockito.MockedStatic;

import javax.jcr.Node;
import javax.jcr.NodeIterator;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * U14 (webauthn half): the registration report is scan-capped at {@code REPORT_SCAN_CAP=5000}, its
 * not-registered list is capped at {@code min(limit, 1000)} with a {@code truncated} flag, and the
 * {@code guest} account is never counted. This is a DoS / user-enumeration limit worth locking.
 * <p>
 * The store hardcodes {@code JCRTemplate.getInstance()} and drives a JCR query, so the static is
 * mocked (mockito-inline) and the JCR query pipeline is faked with {@code javax.jcr} interface
 * proxies (no real repository).
 */
public class WebAuthnRegistrationReportTest {

    private final AtomicLong lastUsersScanLimit = new AtomicLong(-1);

    @Test
    public void report_capsListAtLimit_marksTruncated_andExcludesGuest() throws Exception {
        // 5000 users, none registered, plus guest → total excludes guest; list capped at limit=10.
        WebAuthnCredentialStore.RegistrationReport report = runReport(10, users(5000), noCredentials());

        assertEquals("guest must be excluded from the scanned total", 5000L, report.getTotalUsers());
        assertEquals(0L, report.getRegisteredUsers());
        assertEquals("not-registered list capped at the requested limit", 10, report.getNotRegistered().size());
        assertTrue("more unregistered users than the list cap → truncated", report.isTruncated());
        assertFalse(report.getNotRegistered().contains("guest"));
        assertEquals("the jnt:user scan must be capped at REPORT_SCAN_CAP", 5000L, lastUsersScanLimit.get());
    }

    @Test
    public void report_notRegisteredListHardCapIsOneThousand() throws Exception {
        // limit above 1000 must still cap the returned list at 1000.
        WebAuthnCredentialStore.RegistrationReport report = runReport(5000, users(5000), noCredentials());
        assertEquals("the not-registered list is hard-capped at 1000", 1000, report.getNotRegistered().size());
        assertTrue(report.isTruncated());
    }

    @Test
    public void report_countsRegisteredUsersAndOmitsThemFromNotRegistered() throws Exception {
        // 3 users, 2 of them own a credential → only 1 not-registered, not truncated.
        WebAuthnCredentialStore.RegistrationReport report =
                runReport(50, users(3), credentialsOwnedBy("user1", "user2"));
        assertEquals(3L, report.getTotalUsers());
        assertEquals(2L, report.getRegisteredUsers());
        assertEquals(1, report.getNotRegistered().size());
        assertTrue(report.getNotRegistered().contains("user3"));
        assertFalse(report.isTruncated());
    }

    // --- harness --------------------------------------------------------------------------------

    private WebAuthnCredentialStore.RegistrationReport runReport(int limit, List<String> userNames,
                                                                 List<String> credentialOwners) throws Exception {
        WebAuthnCredentialStore store = new WebAuthnCredentialStore();
        JCRWorkspaceWrapper workspace = workspace(userNames, credentialOwners); // build before stubbing (no nested when())
        JCRSessionWrapper session = mock(JCRSessionWrapper.class);
        when(session.getWorkspace()).thenReturn(workspace);

        JCRTemplate template = mock(JCRTemplate.class);
        when(template.doExecuteWithSystemSession(any())).thenAnswer(inv ->
                inv.getArgument(0, JCRCallback.class).doInJCR(session));

        try (MockedStatic<JCRTemplate> statics = mockStatic(JCRTemplate.class)) {
            statics.when(JCRTemplate::getInstance).thenReturn(template);
            return store.buildRegistrationReport(limit);
        }
    }

    private JCRWorkspaceWrapper workspace(List<String> userNames, List<String> credentialOwners) throws Exception {
        QueryWrapper credQuery = query(credentialNodes(credentialOwners), null);
        QueryWrapper userQuery = query(userNodes(userNames), lastUsersScanLimit);

        QueryManagerWrapper qm = mock(QueryManagerWrapper.class);
        when(qm.createQuery(argThat(sql -> sql != null && sql.contains(WebAuthnCredentialStore.NT_CREDENTIAL)), any()))
                .thenReturn(credQuery);
        when(qm.createQuery(argThat(sql -> sql != null && sql.contains("jnt:user")), any()))
                .thenReturn(userQuery);

        JCRWorkspaceWrapper ws = mock(JCRWorkspaceWrapper.class);
        when(ws.getQueryManager()).thenReturn(qm);
        return ws;
    }

    private static QueryWrapper query(List<Node> nodes, AtomicLong limitSink) throws Exception {
        QueryResultWrapper result = mock(QueryResultWrapper.class);
        when(result.getNodes()).thenReturn(nodeIterator(nodes));
        QueryWrapper query = mock(QueryWrapper.class);
        when(query.execute()).thenReturn(result);
        if (limitSink != null) {
            doAnswer(inv -> {
                limitSink.set(inv.getArgument(0));
                return null;
            }).when(query).setLimit(anyLong());
        }
        return query;
    }

    private static JCRNodeIteratorWrapper nodeIterator(List<Node> nodes) {
        int[] cursor = {0};
        return (JCRNodeIteratorWrapper) Proxy.newProxyInstance(WebAuthnRegistrationReportTest.class.getClassLoader(),
                new Class<?>[]{JCRNodeIteratorWrapper.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "hasNext":
                            return cursor[0] < nodes.size();
                        case "nextNode":
                        case "next":
                            return nodes.get(cursor[0]++);
                        case "getSize":
                            return (long) nodes.size();
                        default:
                            return null;
                    }
                });
    }

    /** A user node whose {@code getName()} is {@code name}. */
    private static Node userNode(String name) {
        return (Node) Proxy.newProxyInstance(WebAuthnRegistrationReportTest.class.getClassLoader(),
                new Class<?>[]{Node.class}, (proxy, method, args) ->
                        "getName".equals(method.getName()) ? name : null);
    }

    /** A credential node whose {@code getParent().getName()} is the owning user's name. */
    private static Node credentialNode(String ownerName) {
        Node parent = userNode(ownerName);
        return (Node) Proxy.newProxyInstance(WebAuthnRegistrationReportTest.class.getClassLoader(),
                new Class<?>[]{Node.class}, (proxy, method, args) ->
                        "getParent".equals(method.getName()) ? parent : null);
    }

    private static List<Node> userNodes(List<String> names) {
        List<Node> nodes = new ArrayList<>();
        for (String n : names) {
            nodes.add(userNode(n));
        }
        return nodes;
    }

    private static List<Node> credentialNodes(List<String> owners) {
        List<Node> nodes = new ArrayList<>();
        for (String o : owners) {
            nodes.add(credentialNode(o));
        }
        return nodes;
    }

    private static List<String> users(int count) {
        List<String> names = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            names.add("user" + i);
        }
        names.add("guest"); // must be excluded
        return names;
    }

    private static List<String> noCredentials() {
        return new ArrayList<>();
    }

    private static List<String> credentialsOwnedBy(String... owners) {
        return List.of(owners);
    }
}
