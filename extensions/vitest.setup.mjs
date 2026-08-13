import {afterEach} from 'vitest';
import {cleanup} from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

// Testing Library's automatic per-test cleanup only self-registers when it detects globalThis
// afterEach (e.g. vitest's `test.globals: true`). This project imports test globals explicitly
// instead, so unmount every rendered tree by hand - otherwise a data-testid from test N is still
// in the DOM when test N+1 queries for it ("Found multiple elements").
afterEach(cleanup);
