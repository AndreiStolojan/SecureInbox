import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiClient } from '../../src/api/apiClient.js';
import { setStoredToken } from '../../src/utils/tokenStorage.js';

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe('apiClient', () => {
  it('sends bearer token from storage', async () => {
    setStoredToken('jwt-token');
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(JSON.stringify({ success: true, data: { ok: true } })),
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.get('/users/me');

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/users/me',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer jwt-token',
        }),
      })
    );
  });

  it('throws normalized backend errors', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        text: () =>
          Promise.resolve(
            JSON.stringify({
              success: false,
              message: 'Validation failed',
              code: 'VALIDATION_ERROR',
            })
          ),
      })
    );

    await expect(apiClient.get('/emails')).rejects.toMatchObject({
      message: 'Validation failed',
      code: 'VALIDATION_ERROR',
      statusCode: 400,
    });
  });

  it.each([504, 524])(
    'does not expose an HTML gateway error document to the UI for status %s',
    async (status) => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: false,
          status,
          text: () => Promise.resolve('<!DOCTYPE html><title>Gateway time-out</title>'),
        })
      );

      await expect(apiClient.post('/scans/emails/example')).rejects.toMatchObject({
        message: 'The server is still processing this request. Please wait a moment and try again.',
        statusCode: status,
      });
    }
  );
});

it('does not let an old AUTH_401 log out the replacement session', async () => {
  setStoredToken('A');
  const pending = Promise.withResolvers();
  vi.stubGlobal('fetch', vi.fn(() => pending.promise));
  const request = apiClient.get('/emails');
  setStoredToken('B');
  pending.resolve({ ok: false, status: 401, text: async () => JSON.stringify({ code: 'AUTH_EXPIRED' }) });
  await expect(request).rejects.toMatchObject({ statusCode: 401 });
  expect(window.localStorage.getItem('secureinbox_token')).toBe('B');
});

it.each([['AUTH_EXPIRED', null], ['GMAIL_EXPIRED', 'A']])('handles current-session %s without confusing Gmail and app auth', async (code, expected) => {
  setStoredToken('A');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 401, text: async () => JSON.stringify({ code }) }));
  await expect(apiClient.get('/emails')).rejects.toMatchObject({ code });
  expect(window.localStorage.getItem('secureinbox_token')).toBe(expected);
});
