package org.jahia.modules.upa.mfa.totp;

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
 * U14 (totp half): the enrollment report is scan-capped at {@code REPORT_SCAN_CAP=5000}, its
 * not-enrolled list is capped at {@code min(limit,1000)} with a {@code truncated} flag, and the
 * {@code guest} account is never counted. DoS / user-enumeration limit worth locking.
 * <p>
 * {@code TotpUserStore} hardcodes {@code JCRTemplate.getInstance()} and drives a JCR query, so the
 * static is mocked (mockito-inline) and the JCR query pipeline is faked with the Jahia wrapper
 * types (no real repository).
 */
public class TotpEnrollmentReportTest {

    private final AtomicLong lastUsersScanLimit = new AtomicLong(-1);

    @Test
    public void report_capsListAtLimit_marksTruncated_andExcludesGuest() throws Exception {
        TotpUserStore.EnrollmentReport report = runReport(10, users(5000), enrolled());

        assertEquals("guest must be excluded from the scanned total", 5000L, report.getTotalUsers());
        assertEquals(0L, report.getEnrolledUsers());
        assertEquals("not-enrolled list capped at the requested limit", 10, report.getNotEnrolled().size());
        assertTrue("more unenrolled users than the list cap → truncated", report.isTruncated());
        assertFalse(report.getNotEnrolled().contains("guest"));
        assertEquals("the jnt:user scan must be capped at REPORT_SCAN_CAP", 5000L, lastUsersScanLimit.get());
    }

    @Test
    public void report_notEnrolledListHardCapIsOneThousand() throws Exception {
        TotpUserStore.EnrollmentReport report = runReport(5000, users(5000), enrolled());
        assertEquals("the not-enrolled list is hard-capped at 1000", 1000, report.getNotEnrolled().size());
        assertTrue(report.isTruncated());
    }

    @Test
    public void report_countsEnrolledUsersAndOmitsThemFromNotEnrolled() throws Exception {
        TotpUserStore.EnrollmentReport report = runReport(50, users(3), enrolled("user1", "user2"));
        assertEquals(3L, report.getTotalUsers());
        assertEquals(2L, report.getEnrolledUsers());
        assertEquals(1, report.getNotEnrolled().size());
        assertTrue(report.getNotEnrolled().contains("user3"));
        assertFalse(report.isTruncated());
    }

    // --- harness --------------------------------------------------------------------------------

    private TotpUserStore.EnrollmentReport runReport(int limit, List<String> userNames,
                                                     List<String> enrolledNames) throws Exception {
        TotpUserStore store = new TotpUserStore();
        JCRWorkspaceWrapper workspace = workspace(userNames, enrolledNames);
        JCRSessionWrapper session = mock(JCRSessionWrapper.class);
        when(session.getWorkspace()).thenReturn(workspace);

        JCRTemplate template = mock(JCRTemplate.class);
        when(template.doExecuteWithSystemSession(any())).thenAnswer(inv ->
                inv.getArgument(0, JCRCallback.class).doInJCR(session));

        try (MockedStatic<JCRTemplate> statics = mockStatic(JCRTemplate.class)) {
            statics.when(JCRTemplate::getInstance).thenReturn(template);
            return store.buildEnrollmentReport(limit);
        }
    }

    private JCRWorkspaceWrapper workspace(List<String> userNames, List<String> enrolledNames) throws Exception {
        QueryWrapper enrolledQuery = query(named(enrolledNames), null);
        QueryWrapper usersQuery = query(named(userNames), lastUsersScanLimit);

        QueryManagerWrapper qm = mock(QueryManagerWrapper.class);
        when(qm.createQuery(argThat(sql -> sql != null && sql.contains(TotpUserStore.MIXIN_USER_SETTINGS)), any()))
                .thenReturn(enrolledQuery);
        when(qm.createQuery(argThat(sql -> sql != null && sql.contains("jnt:user")), any()))
                .thenReturn(usersQuery);

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
        return (JCRNodeIteratorWrapper) Proxy.newProxyInstance(TotpEnrollmentReportTest.class.getClassLoader(),
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

    /** A node whose {@code getName()} is {@code name} (both the enrolled-settings and user nodes). */
    private static Node namedNode(String name) {
        return (Node) Proxy.newProxyInstance(TotpEnrollmentReportTest.class.getClassLoader(),
                new Class<?>[]{Node.class}, (proxy, method, args) ->
                        "getName".equals(method.getName()) ? name : null);
    }

    private static List<Node> named(List<String> names) {
        List<Node> nodes = new ArrayList<>();
        for (String n : names) {
            nodes.add(namedNode(n));
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

    private static List<String> enrolled(String... names) {
        return new ArrayList<>(List.of(names));
    }
}
