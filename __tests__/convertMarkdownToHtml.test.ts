// Mock side-effectful modules used at import time
jest.mock('../src/oauth2.ts', () => ({
  createOAuth2Client: () => null,
  launchAuthServer: jest.fn(),
  validateCredentials: jest.fn(async () => true),
}))

jest.mock('fs', () => ({
  appendFileSync: jest.fn(),
}))

jest.mock('googleapis', () => ({
  google: { gmail: jest.fn() },
  gmail_v1: {},
}))

import { convertMarkdownToHtml } from '../src/index'

describe('convertMarkdownToHtml', () => {
  test('escapes HTML and preserves newlines as <br>', () => {
    const input = 'Hello <b>world</b> & "quotes"\nNew line'
    const html = convertMarkdownToHtml(input)
    expect(html).toBe('Hello &lt;b&gt;world&lt;/b&gt; &amp; &quot;quotes&quot;<br>New line')
  })

  test('converts markdown links; adds https scheme if missing', () => {
    const input = 'Visit [OpenAI](openai.com) and [Docs](https://platform.openai.com/)'
    const html = convertMarkdownToHtml(input)
    expect(html).toBe(
      'Visit <a href="https://openai.com" target="_blank">OpenAI</a> and <a href="https://platform.openai.com/" target="_blank">Docs</a>'
    )
  })

  test('converts plain URLs, escapes ampersands, and preserves trailing punctuation', () => {
    const input = 'Check https://example.com/path?x=1&y=2, and www.test.com.'
    const html = convertMarkdownToHtml(input)
    expect(html).toBe(
      'Check <a href="https://example.com/path?x=1&amp;y=2" target="_blank">https://example.com/path?x=1&amp;y=2</a>, and <a href="https://www.test.com" target="_blank">www.test.com</a>.'
    )
  })

  test('handles bold and italics and doesn’t break anchors or underscores', () => {
    const input = 'This is **bold** and *italic* and __bold__ and _italic_ and *[x](http://a.com)* and http://a.com/path_with_underscores'
    const html = convertMarkdownToHtml(input)
    expect(html).toBe(
      'This is <strong>bold</strong> and <em>italic</em> and <strong>bold</strong> and <em>italic</em> and <em><a href="http://a.com" target="_blank">x</a></em> and <a href="http://a.com/path_with_underscores" target="_blank">http://a.com/path_with_underscores</a>'
    )
  })

  test('applies click tracking to markdown and plain URLs', () => {
    const tracker = 'https://tracker.example/clk'
    const input = 'See [A](https://a.com) and www.b.com/path'
    const html = convertMarkdownToHtml(input, tracker)
    expect(html).toBe(
      `See <a href="${tracker}?url=${encodeURIComponent('https://a.com')}" target="_blank">A</a> and <a href="${tracker}?url=${encodeURIComponent('https://www.b.com/path')}" target="_blank">www.b.com/path</a>`
    )
  })

  test('handles https://www.* and www.* consistently (no double scheme)', () => {
    const input = 'Visit https://www.example.com, also www.example.org/test.'
    const html = convertMarkdownToHtml(input)
    expect(html).toBe(
      'Visit <a href="https://www.example.com" target="_blank">https://www.example.com</a>, also <a href="https://www.example.org/test" target="_blank">www.example.org/test</a>.'
    )
  })

  test('markdown links with underscores in URL and text', () => {
    const input = 'Open [release_notes_v1](https://docs.example.com/release_notes_v1?x_a=1&y_b=2)'
    const html = convertMarkdownToHtml(input)
    expect(html).toBe(
      'Open <a href="https://docs.example.com/release_notes_v1?x_a=1&amp;y_b=2" target="_blank">release_notes_v1</a>'
    )
  })

  test('plain URLs with underscores are not italicized and preserve underscores', () => {
    const input = 'URL: https://api.example.com/v1/get_user_profile and note _this_ is italic'
    const html = convertMarkdownToHtml(input)
    expect(html).toBe(
      'URL: <a href="https://api.example.com/v1/get_user_profile" target="_blank">https://api.example.com/v1/get_user_profile</a> and note <em>this</em> is italic'
    )
  })

  test('tracking preserves trailing punctuation with https://www.* and underscores', () => {
    const tracker = 'https://tracker.tld/click'
    const input = 'See https://www.c.com/path_end, and www.d.com/with_under_score_.'
    const html = convertMarkdownToHtml(input, tracker)
    expect(html).toBe(
      `See <a href="${tracker}?url=${encodeURIComponent('https://www.c.com/path_end')}" target="_blank">https://www.c.com/path_end</a>, and <a href="${tracker}?url=${encodeURIComponent('https://www.d.com/with_under_score_')}" target="_blank">www.d.com/with_under_score_</a>.`
    )
  })
})
