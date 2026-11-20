import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockOr, mockGetServiceRoleClient } = vi.hoisted(() => ({
    mockOr: vi.fn(),
    mockGetServiceRoleClient: vi.fn(),
}));

vi.mock('@/lib/serverAuth', () => ({
    requireAuthenticatedRequest: vi.fn().mockResolvedValue({
        ok: true,
        userId: 'user-inst-search',
        user: { id: 'user-inst-search' },
        accessToken: 'tok',
    }),
    hasServiceRoleEnv: () => true,
    getServiceRoleClient: mockGetServiceRoleClient,
}));

vi.mock('@/lib/rateLimit', () => ({
    enforceRateLimit: vi.fn().mockResolvedValue(null),
    resetRateLimitStore: vi.fn(),
}));

vi.mock('@/lib/institutionMembership', () => ({
    resolveInstitutionForUser: vi.fn().mockResolvedValue({
        institutionId: 'inst-1',
        role: 'admin',
    }),
}));

vi.mock('@/lib/debug', () => ({
    captureException: vi.fn(),
    structuredLog: vi.fn(),
}));

import { GET } from '@/app/api/institution/credentials/route';

function makeRequest(search: string): Request {
    const url = `http://localhost/api/institution/credentials?search=${encodeURIComponent(search)}`;
    return new Request(url, { headers: { 'x-forwarded-for': '198.51.100.7' } });
}

function makeSupabase() {
    const query: Record<string, unknown> = {};
    const chainable = ['select', 'eq', 'order', 'range', 'gte', 'lte'];
    for (const method of chainable) query[method] = () => query;
    query.or = (filter: string) => {
        mockOr(filter);
        return query;
    };
    query.then = (resolve: (value: unknown) => void) =>
        resolve({ data: [], error: null, count: 0 });

    return {
        from: () => query,
    };
}

/** The `or(...)` filter string the route built for a given search term. */
async function filterFor(search: string): Promise<string> {
    const res = await GET(makeRequest(search) as Parameters<typeof GET>[0]);
    expect(res.status).toBe(200);
    expect(mockOr).toHaveBeenCalledTimes(1);
    return mockOr.mock.calls[0][0] as string;
}

describe('GET /api/institution/credentials search sanitization', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockGetServiceRoleClient.mockReturnValue(makeSupabase());
    });

    it('builds the usual ilike filter for a plain search term', async () => {
        const filter = await filterFor('Alice');
        expect(filter).toBe(
            'token_id.ilike.%Alice%,' +
                'metadata->credentialData->>studentName.ilike.%Alice%,' +
                'metadata->credentialData->>degree.ilike.%Alice%,' +
                'metadata->credentialData->>credentialType.ilike.%Alice%',
        );
    });

    it('replaces commas so they cannot add extra or() filters', async () => {
        const filter = await filterFor('Alice,token_id.eq.x');
        expect(filter).not.toContain(',token_id.eq.x');
        expect(filter).not.toContain('Alice,token_id');
        expect(filter).toContain('ilike.%Alice token_id.eq.x%');
        // Still exactly the four intended filters: three separators remain.
        expect(filter.split(',').length).toBe(4);
    });

    it('replaces parentheses so they cannot close or open grouping', async () => {
        const filter = await filterFor('Smith(Jr)');
        expect(filter).not.toMatch(/[()]/);
        expect(filter).toContain('ilike.%Smith Jr%');
    });

    it('replaces backslashes so they cannot escape a delimiter', async () => {
        const filter = await filterFor('a\\,b');
        expect(filter).not.toContain('\\');
        expect(filter).toContain('ilike.%a  b%');
        expect(filter.split(',').length).toBe(4);
    });

    it('treats a delimiter-heavy term as literal text', async () => {
        const filter = await filterFor('Doe, Jane (PhD)\\');
        expect(filter).not.toMatch(/[()\\]/);
        expect(filter.split(',').length).toBe(4);
        expect(filter).toBe(
            'token_id.ilike.%Doe  Jane  PhD%,' +
                'metadata->credentialData->>studentName.ilike.%Doe  Jane  PhD%,' +
                'metadata->credentialData->>degree.ilike.%Doe  Jane  PhD%,' +
                'metadata->credentialData->>credentialType.ilike.%Doe  Jane  PhD%',
        );
    });

    it('skips the filter entirely when the term is only delimiters', async () => {
        const res = await GET(makeRequest(',()\\') as Parameters<typeof GET>[0]);
        expect(res.status).toBe(200);
        expect(mockOr).not.toHaveBeenCalled();
    });

    it('skips the filter when search is blank or whitespace', async () => {
        for (const search of ['', '   ']) {
            mockOr.mockClear();
            const res = await GET(makeRequest(search) as Parameters<typeof GET>[0]);
            expect(res.status).toBe(200);
            expect(mockOr).not.toHaveBeenCalled();
        }
    });
});
