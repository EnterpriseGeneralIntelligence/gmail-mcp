#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { createStatelessServer } from "@smithery/sdk/server/stateless.js"
import { z } from "zod"
import { google, gmail_v1 } from 'googleapis'
import fs from "fs"
import { createOAuth2Client, launchAuthServer, validateCredentials } from "./oauth2.js"
import { MCP_CONFIG_DIR, PORT, LOG_FILE_PATH } from "./config.js"

type Draft = gmail_v1.Schema$Draft
type DraftCreateParams = gmail_v1.Params$Resource$Users$Drafts$Create
type DraftUpdateParams = gmail_v1.Params$Resource$Users$Drafts$Update
type Message = gmail_v1.Schema$Message
type MessagePart = gmail_v1.Schema$MessagePart
type MessagePartBody = gmail_v1.Schema$MessagePartBody
type MessagePartHeader = gmail_v1.Schema$MessagePartHeader
type MessageSendParams = gmail_v1.Params$Resource$Users$Messages$Send
type Thread = gmail_v1.Schema$Thread

type NewMessage = {
  threadId?: string
  raw?: string
  to?: string[] | undefined
  cc?: string[] | undefined
  bcc?: string[] | undefined
  subject?: string | undefined
  body?: string | undefined
}

const RESPONSE_HEADERS_LIST = [
  'Date',
  'From',
  'To',
  'Cc',
  'Bcc',
  'Subject',
  'Message-ID',
  'In-Reply-To',
  'References'
]

const defaultOAuth2Client = createOAuth2Client()

const defaultGmailClient = defaultOAuth2Client ? google.gmail({ version: 'v1', auth: defaultOAuth2Client }) : null

const formatResponse = (response: any) => ({ content: [{ type: "text", text: JSON.stringify(response) }] })

const logToFile = (message: string, data: any) => {
  const timestamp = new Date().toISOString()
  const logEntry = `[${timestamp}] ${message}: ${JSON.stringify(data)}\n`
  fs.appendFileSync(LOG_FILE_PATH, logEntry)
}

const handleTool = async (queryConfig: Record<string, any> | undefined, apiCall: (gmail: gmail_v1.Gmail) => Promise<any>) => {
  const oauth2Client = queryConfig ? createOAuth2Client(queryConfig) : defaultOAuth2Client
  if (!oauth2Client) throw new Error('OAuth2 client could not be created, please check your credentials')

  const credentialsAreValid = await validateCredentials(oauth2Client)
  if (!credentialsAreValid) throw new Error('OAuth2 credentials are invalid, please re-authenticate')

  const gmailClient = queryConfig ? google.gmail({ version: 'v1', auth: oauth2Client }) : defaultGmailClient
  if (!gmailClient) throw new Error('Gmail client could not be created, please check your credentials')

  const result = await apiCall(gmailClient)
  return result
}

const decodedBody = (body: MessagePartBody) => {
  if (!body?.data) return body

  const decodedData = Buffer.from(body.data, 'base64').toString('utf-8')
  const decodedBody: MessagePartBody = {
    data: decodedData,
    size: body.data.length,
    attachmentId: body.attachmentId
  }
  return decodedBody
}

const processMessagePart = (messagePart: MessagePart): MessagePart => {
  if (messagePart.mimeType !== 'text/html' && messagePart.body) {
    messagePart.body = decodedBody(messagePart.body)
  }

  if (messagePart.parts) {
    messagePart.parts = messagePart.parts.map(part => processMessagePart(part))
  }

  if (messagePart.headers) {
    messagePart.headers = messagePart.headers.filter(header => RESPONSE_HEADERS_LIST.includes(header.name || ''))
  }

  return messagePart
}

const htmlToPlainText = (html: string): string => {
  return html
    // Remove script and style elements completely
    .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, '')
    // Convert common HTML elements to plain text equivalents
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/?(p|div|h[1-6])[^>]*>/gi, '\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<li[^>]*>/gi, '• ')
    // Remove all other HTML tags
    .replace(/<[^>]*>/g, '')
    // Decode HTML entities
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    // Clean up extra whitespace
    .replace(/\n\s*\n/g, '\n')
    .trim()
}

const extractMessageContent = (messagePart: MessagePart): { text: string, html?: string } => {
  let textContent = []
  let htmlContent: string | undefined = undefined

  // Check if current part has text content
  if (messagePart.mimeType === 'text/plain' && messagePart.body?.data) {
    const { data } = decodedBody(messagePart.body)
    if (data) {
      // For plain text, use the traditional > prefix for quoting
      textContent.push(data.split('\n').map(line => '> ' + line).join('\n'))
    }
  } else if (messagePart.mimeType === 'text/html' && messagePart.body?.data) {
    const { data } = decodedBody(messagePart.body)
    if (data) {
      // For HTML, keep the original HTML content for blockquote wrapping
      htmlContent = data
      // Also create a plain text version for fallback
      const plainText = htmlToPlainText(data)
      textContent.push(plainText.split('\n').map(line => '> ' + line).join('\n'))
    }
  }

  // Recursively process nested parts to find the best content
  if (messagePart.parts && messagePart.parts.length > 0) {
    // Prefer text/plain over text/html for quoting
    const textPart = messagePart.parts.find(part => part.mimeType === 'text/plain')
    const htmlPart = messagePart.parts.find(part => part.mimeType === 'text/html')

    if (textPart) {
      const textResult = extractMessageContent(textPart)
      if (textResult.text) textContent.push(textResult.text)
    } else if (htmlPart) {
      const htmlResult = extractMessageContent(htmlPart)
      if (htmlResult.text) textContent.push(htmlResult.text)
      if (htmlResult.html) htmlContent = htmlResult.html
    } else {
      // Process other parts recursively
      const nestedResults = messagePart.parts
        .map(part => extractMessageContent(part))
        .filter(result => result.text.trim())

      if (nestedResults.length > 0) {
        textContent.push(nestedResults.map(result => result.text).join('\n'))
        // Use the first HTML content found
        if (!htmlContent) {
          htmlContent = nestedResults.find(result => result.html)?.html
        }
      }
    }
  }

  return {
    text: textContent.join('\n'),
    html: htmlContent
  }
}

const findHeader = (headers: MessagePartHeader[] | undefined, name: string) => {
  if (!headers || !Array.isArray(headers) || !name) return undefined
  return headers.find(h => h?.name?.toLowerCase() === name.toLowerCase())?.value ?? undefined
}

const formatEmailList = (emailList: string | null | undefined) => {
  if (!emailList) return []
  return emailList.split(',').map(email => email.trim())
}

const extractEmailAddress = (emailString: string): string => {
  // Extract email from "Name <email>" format or just return the email if it's plain
  const match = emailString.match(/<([^>]+)>/)
  return match ? match[1] : emailString.trim()
}

const validateEmailHeader = (emails: string[]): string[] => {
  return emails.filter(email => {
    // Check for basic email validity and no problematic characters
    const cleanEmail = email.trim()
    if (!cleanEmail) return false
    
    // Check for control characters, line breaks, or other problematic characters
    if (/[\r\n\t\x00-\x1f\x7f-\x9f]/.test(cleanEmail)) {
      logToFile('validateEmailHeader_invalid_chars', { email: cleanEmail, chars: cleanEmail.match(/[\r\n\t\x00-\x1f\x7f-\x9f]/g) })
      return false
    }
    
    // Basic email format check
    const emailAddr = extractEmailAddress(cleanEmail)
    const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailAddr)
    if (!isValid) {
      logToFile('validateEmailHeader_invalid_format', { email: cleanEmail, extractedEmail: emailAddr })
    }
    return isValid
  })
}

const getQuotedContent = (thread: Thread): { text: string, html?: string } => {
  if (!thread.messages?.length) return { text: '' }

  // Get the last message in the thread (most recent)
  const lastMessage = thread.messages[thread.messages.length - 1]
  if (!lastMessage?.payload) return { text: '' }

  let quotedTextContent = []
  let quotedHtmlContent: string | undefined = undefined

  if (lastMessage.payload.headers) {
    const fromHeader = findHeader(lastMessage.payload.headers || [], 'from')
    const dateHeader = findHeader(lastMessage.payload.headers || [], 'date')
    if (fromHeader && dateHeader) {
      quotedTextContent.push('')
      quotedTextContent.push(`On ${dateHeader} ${fromHeader} wrote:`)
      quotedTextContent.push('')
    }
  }

  const messageContent = extractMessageContent(lastMessage.payload)
  if (messageContent.text) {
    quotedTextContent.push(messageContent.text)
    quotedTextContent.push('')
  }

  if (messageContent.html) {
    // Add the header to HTML content as well
    const fromHeader = findHeader(lastMessage.payload.headers || [], 'from')
    const dateHeader = findHeader(lastMessage.payload.headers || [], 'date')
    if (fromHeader && dateHeader) {
      // Extract email address from the from header (handle both "Name <email>" and "email" formats)
      const emailMatch = fromHeader.match(/<([^>]+)>/)
      const emailAddress = emailMatch ? emailMatch[1] : fromHeader
      quotedHtmlContent = `<div>On ${dateHeader} &lt;${emailAddress}&gt; wrote:</div><br>${messageContent.html}`
    } else {
      quotedHtmlContent = messageContent.html
    }
  }

  return {
    text: quotedTextContent.join('\n'),
    html: quotedHtmlContent
  }
}

const getReplyAllRecipients = (thread: Thread, currentUserEmail: string): { to: string[], cc: string[] } => {
  if (!thread.messages?.length) return { to: [], cc: [] }

  // Get the last message in the thread
  const lastMessage = thread.messages[thread.messages.length - 1]
  if (!lastMessage?.payload?.headers) return { to: [], cc: [] }

  const headers = lastMessage.payload.headers
  const fromHeader = findHeader(headers, 'from')
  const toHeader = findHeader(headers, 'to')
  const ccHeader = findHeader(headers, 'cc')

  // Parse email addresses
  const fromEmails = fromHeader ? formatEmailList(fromHeader) : []
  const toEmails = toHeader ? formatEmailList(toHeader) : []
  const ccEmails = ccHeader ? formatEmailList(ccHeader) : []

  // Check if the last message was sent by the current user
  const wasSentByUser = lastMessage.labelIds?.includes('SENT')

  let toRecipients: string[] = []
  let ccRecipients: string[] = []

  if (wasSentByUser) {
    // If the user sent the last message, reply to the same recipients
    toRecipients = [...toEmails]
    ccRecipients = [...ccEmails]
  } else {
    // If the user received the message, reply to the sender and include all other recipients
    toRecipients = [...fromEmails]

    // Add all original recipients to CC except the current user
    const allCcRecipients = [...toEmails, ...ccEmails].filter(email => {
      // Extract just the email part for comparison (remove display names)
      const emailOnly = email.match(/<([^>]+)>/) ? email.match(/<([^>]+)>/)![1] : email
      return emailOnly.toLowerCase() !== currentUserEmail.toLowerCase()
    })

    ccRecipients = [...new Set(allCcRecipients)] // Remove duplicates
  }

  return { to: toRecipients, cc: ccRecipients }
}


const sanitizeSubject = (subject: string): string => {
  // Remove or replace special characters that can cause issues in email headers
  return subject
    .replace(/[\r\n\t]/g, ' ') // Replace line breaks and tabs with spaces
    .replace(/[^\x20-\x7E]/g, '') // Remove non-ASCII characters
    .replace(/\s+/g, ' ') // Replace multiple spaces with single space
    .trim()
}

const convertMarkdownToHtml = (text: string): string => {
  let html = text
  
  logToFile('convertMarkdownToHtml_start', { 
    input: text 
  })

  // Convert markdown links FIRST before escaping HTML entities
  // This ensures the generated HTML tags are not escaped
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (match, linkText, url) => {
    // Clean and prepare the URL
    const cleanUrl = url.trim()
    
    // Ensure the URL has a protocol (for Gmail compatibility)
    let finalUrl = cleanUrl
    if (!cleanUrl.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:/)) {
      // If no protocol, assume https://
      finalUrl = 'https://' + cleanUrl
    }
    
    // Escape HTML entities in the link text only
    const escapedLinkText = linkText
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
    
    // Return the HTML link with properly encoded URL
    const result = `<a href="${encodeURI(finalUrl)}" target="_blank">${escapedLinkText}</a>`
    
    logToFile('convertMarkdownToHtml_link', {
      match,
      linkText,
      url,
      cleanUrl,
      finalUrl,
      escapedLinkText,
      result
    })
    
    return result
  })

  // Now escape HTML entities in the remaining text (not inside HTML tags)
  // This regex matches text outside of HTML tags
  html = html.replace(/([^<>]+)(?=<|$)/g, (match) => {
    // Skip if this is inside an HTML tag
    if (match.includes('href=') || match.includes('target=')) {
      return match
    }
    return match
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
  })

  // Convert bold syntax: **text** or __text__
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/__([^_]+)__/g, '<strong>$1</strong>')

  // Convert italic syntax: *text* or _text_ (but not if part of bold)
  // Use negative lookbehind and lookahead to avoid matching bold syntax
  html = html.replace(/(?<!\*)\*(?!\*)([^*]+)(?<!\*)\*(?!\*)/g, '<em>$1</em>')
  html = html.replace(/(?<!_)_(?!_)([^_]+)(?<!_)_(?!_)/g, '<em>$1</em>')

  // Convert line breaks to <br>
  html = html.replace(/\n/g, '<br>')
  
  logToFile('convertMarkdownToHtml_final', { 
    output: html 
  })

  return html
}

const stripMarkdownToPlainText = (text: string): string => {
  // Remove markdown links: [text](url) -> text
  let plainText = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1')

  // Remove bold syntax: **text** or __text__
  plainText = plainText.replace(/\*\*([^*]+)\*\*/g, '$1')
  plainText = plainText.replace(/__([^_]+)__/g, '$1')

  // Remove italic syntax: *text* or _text_
  plainText = plainText.replace(/(?<!\*)\*(?!\*)([^*]+)(?<!\*)\*(?!\*)/g, '$1')
  plainText = plainText.replace(/(?<!_)_(?!_)([^_]+)(?<!_)_(?!_)/g, '$1')

  return plainText
}

const wrapTextBody = (text: string): string => {
  // For quoted-printable encoding, we need to:
  // 1. Convert string to UTF-8 bytes
  // 2. Encode = character first
  // 3. Then encode other special characters
  // 4. Wrap lines at 76 characters
  
  // Convert string to UTF-8 bytes
  const utf8Bytes = Buffer.from(text, 'utf8')
  
  let encoded = ''
  for (let i = 0; i < utf8Bytes.length; i++) {
    const byte = utf8Bytes[i]
    
    // Check if byte needs encoding
    if (byte === 0x3D) { // = character
      encoded += '=3D'
    } else if (byte === 0x09 || (byte >= 0x20 && byte <= 0x7E)) { // Tab or printable ASCII
      encoded += String.fromCharCode(byte)
    } else {
      // Encode as =XX
      const hex = byte.toString(16).toUpperCase()
      encoded += '=' + (hex.length < 2 ? '0' + hex : hex)
    }
  }
    
  // Wrap lines at 76 characters for quoted-printable
  return encoded.split('\n').map(line => {
    if (line.length <= 76) return line
    
    const chunks = []
    let currentChunk = ''
    
    for (let i = 0; i < line.length; i++) {
      currentChunk += line[i]
      // Don't break in the middle of an encoded sequence (=XX)
      if (currentChunk.length >= 73 && line[i] !== '=' && 
          !(i > 0 && line[i-1] === '=') && 
          !(i > 1 && line[i-2] === '=')) {
        chunks.push(currentChunk + '=')
        currentChunk = ''
      }
    }
    
    if (currentChunk) chunks.push(currentChunk)
    return chunks.join('\n')
  }).join('\n')
}

const constructRawMessage = async (gmail: gmail_v1.Gmail, params: NewMessage) => {
  logToFile('constructRawMessage_start', { params: { ...params, body: params.body ? params.body.substring(0, 100) + (params.body.length > 100 ? '...' : '') : undefined } })

  let thread: Thread | null = null
  let userProfile: any = null
  let validThreadId: string | undefined = undefined

  // Get user's email address for reply-all logic
  try {
    const profileResponse = await gmail.users.getProfile({ userId: 'me' })
    userProfile = profileResponse.data
    logToFile('constructRawMessage_profile', { emailAddress: userProfile?.emailAddress })
  } catch (error) {
    console.error('Failed to get user profile:', error)
  }

  const userEmail = userProfile?.emailAddress || ''

  if (params.threadId) {
    logToFile('constructRawMessage_thread_lookup', { threadId: params.threadId })
    try {
      const threadParams = { userId: 'me', id: params.threadId, format: 'full' }
      const { data } = await gmail.users.threads.get(threadParams)
      thread = data
      // Only set validThreadId if the thread was successfully fetched
      validThreadId = params.threadId
      logToFile('constructRawMessage_thread_found', { threadId: validThreadId, messageCount: thread?.messages?.length })
    } catch (error) {
      // If thread doesn't exist, ignore the threadId and create a new thread
      thread = null
      validThreadId = undefined
    }
  }

  // Generate a boundary string for multipart messages
  const boundary = `boundary_${Date.now().toString(16)}`
  logToFile('constructRawMessage_boundary', { boundary })

  // Start building the message headers
  const message = []

  // For replies to threads, implement reply-all behavior
  if (thread && thread.messages?.length) {
    logToFile('constructRawMessage_reply_mode', { threadId: validThreadId })
    const { to: replyToRecipients, cc: replyCcRecipients } = getReplyAllRecipients(thread, userEmail)
    logToFile('constructRawMessage_reply_recipients', {
      replyToRecipients: replyToRecipients.length,
      replyCcRecipients: replyCcRecipients.length
    })

    // Merge explicitly provided recipients with those from reply-all logic
    let toRecipients: string[] = [...(params.to || [])]
    const toEmails = new Set(toRecipients.map(extractEmailAddress))
    replyToRecipients.forEach(email => {
      const emailAddr = extractEmailAddress(email)
      if (!toEmails.has(emailAddr)) {
        toRecipients.push(email)
        toEmails.add(emailAddr)
      }
    })
    if (toRecipients.length) message.push(`To: ${wrapTextBody(toRecipients.join(', '))}`)

    // Handle CC recipients - combine from thread reply-all and new params
    let ccRecipients: string[] = [...(params.cc || [])]
    const ccEmails = new Set(ccRecipients.map(extractEmailAddress))
    replyCcRecipients.forEach(email => {
      const emailAddr = extractEmailAddress(email)
      if (!ccEmails.has(emailAddr)) {
        ccRecipients.push(email)
        ccEmails.add(emailAddr)
      }
    })
    
    // Extract just email addresses for CC header (no display names)
    const toEmailAddresses = toRecipients.map(extractEmailAddress)
    const ccEmailAddresses = ccRecipients.map(extractEmailAddress)
    
    // Remove CC recipients that are already in TO
    const filteredCcEmails = ccEmailAddresses.filter(ccEmail => !toEmailAddresses.includes(ccEmail))
    
    logToFile('constructRawMessage_cc_extracted', { 
      originalCcRecipients: ccRecipients,
      extractedCcEmails: ccEmailAddresses,
      toEmails: toEmailAddresses,
      filteredCcEmails: filteredCcEmails,
      ccCount: filteredCcEmails.length 
    })
    
    if (filteredCcEmails.length) message.push(`Cc: ${wrapTextBody(filteredCcEmails.join(', '))}`)

    logToFile('constructRawMessage_final_recipients', {
      toCount: toRecipients.length,
      ccCount: ccRecipients.length,
      ccRecipients: ccRecipients
    })
  } else {
    logToFile('constructRawMessage_new_message_mode', {
      toCount: params.to?.length || 0,
      ccCount: params.cc?.length || 0,
      ccRecipients: params.cc || []
    })
    // For new messages, just use the provided recipients
    if (params.to?.length) message.push(`To: ${wrapTextBody(params.to.join(', '))}`)
    if (params.cc?.length) {
      // Extract just email addresses for CC header (no display names)
      const toEmailAddresses = (params.to || []).map(extractEmailAddress)
      const ccEmailAddresses = params.cc.map(extractEmailAddress)
      
      // Remove CC recipients that are already in TO
      const filteredCcEmails = ccEmailAddresses.filter(ccEmail => !toEmailAddresses.includes(ccEmail))
      
      logToFile('constructRawMessage_new_message_cc_extracted', { 
        originalCc: params.cc,
        extractedCcEmails: ccEmailAddresses,
        toEmails: toEmailAddresses,
        filteredCcEmails: filteredCcEmails
      })
      if (filteredCcEmails.length) message.push(`Cc: ${wrapTextBody(filteredCcEmails.join(', '))}`)
    }
  }

  // Handle BCC recipients
  if (params.bcc?.length) {
    // Extract just email addresses for BCC header (no display names)
    const bccEmailAddresses = params.bcc.map(extractEmailAddress)
    logToFile('constructRawMessage_bcc_extracted', {
      originalBcc: params.bcc,
      extractedBccEmails: bccEmailAddresses,
      bccCount: bccEmailAddresses.length
    })
    if (bccEmailAddresses.length) message.push(`Bcc: ${wrapTextBody(bccEmailAddresses.join(', '))}`)
  }

  // Handle threading headers for proper conversation grouping
  let subjectHeader = '(No Subject)'
  if (thread && thread.messages?.length) {
    logToFile('constructRawMessage_threading_headers', { messageCount: thread.messages.length })
    // Get the first message in the thread to extract headers
    const firstMessage = thread.messages[0];
    const lastMessage = thread.messages[thread.messages.length - 1];

    // Add subject with Re: prefix if needed
    subjectHeader = findHeader(lastMessage.payload?.headers || [], 'subject') || params.subject || '(No Subject)';
    const originalSubject = subjectHeader;
    if (subjectHeader && !subjectHeader.toLowerCase().startsWith('re:')) {
      subjectHeader = `Re: ${subjectHeader}`;
    }
    message.push(`Subject: ${wrapTextBody(sanitizeSubject(subjectHeader))}`);
    logToFile('constructRawMessage_subject', { originalSubject, finalSubject: subjectHeader })

    // Add critical threading headers
    const references: string[] = [];

    // Collect all Message-IDs from the thread
    thread.messages.forEach(msg => {
      const msgId = findHeader(msg.payload?.headers || [], 'message-id');
      if (msgId) references.push(msgId);
    });

    // Add In-Reply-To header (points to the last message in the thread)
    const lastMessageId = findHeader(lastMessage.payload?.headers || [], 'message-id');
    if (lastMessageId) {
      message.push(`In-Reply-To: ${lastMessageId}`);
      logToFile('constructRawMessage_in_reply_to', { lastMessageId })
    }

    // Add References header with all message IDs in the thread
    if (references.length > 0) {
      message.push(`References: ${references.join(' ')}`);
      logToFile('constructRawMessage_references', { referenceCount: references.length })
    }
  } else if (params.subject) {
    subjectHeader = params.subject
    message.push(`Subject: ${wrapTextBody(sanitizeSubject(params.subject))}`)
    logToFile('constructRawMessage_new_subject', { subject: params.subject })
  } else {
    message.push('Subject: (No Subject)')
    logToFile('constructRawMessage_no_subject', {})
  }

  // Set up multipart MIME message
  message.push('MIME-Version: 1.0')
  message.push(`Content-Type: multipart/alternative; boundary=${boundary}`)
  message.push('')
  message.push(`--${boundary}`)
  logToFile('constructRawMessage_mime_setup', { boundary })

  // Add text/plain part
  message.push('Content-Type: text/plain; charset="UTF-8"')
  message.push('Content-Transfer-Encoding: quoted-printable')
  message.push('')

  // Add the body content (strip markdown for plain text version)
  if (params.body) {
    const plainTextBody = stripMarkdownToPlainText(params.body)
    message.push(wrapTextBody(plainTextBody))
    logToFile('constructRawMessage_plain_text_body', { bodyLength: plainTextBody.length })
  }

  // Add quoted content for replies
  if (thread) {
    const quotedContent = getQuotedContent(thread)
    if (quotedContent.text) {
      message.push('')
      message.push(wrapTextBody(quotedContent.text))
      logToFile('constructRawMessage_quoted_content_text', { quotedLength: quotedContent.text.length })
    }
  }

  // Add HTML part
  message.push('')
  message.push(`--${boundary}`)
  message.push('Content-Type: text/html; charset="UTF-8"')
  message.push('Content-Transfer-Encoding: quoted-printable')
  message.push('')
  logToFile('constructRawMessage_html_part_start', {})

  // Convert plain text to HTML with markdown formatting
  let htmlBody = ''
  if (params.body) {
    // Convert markdown syntax to HTML
    htmlBody = convertMarkdownToHtml(params.body)
    logToFile('constructRawMessage_html_body', { 
      htmlLength: htmlBody.length,
      originalBody: params.body,
      convertedHtml: htmlBody
    })
  }

  // Add HTML body with Gmail-compatible quoted content formatting
  // Wrap the entire HTML content for quoted-printable encoding
  const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
</head>
<body>
  <div>${htmlBody}</div>`
  
  message.push(wrapTextBody(htmlContent))

  // Add quoted content in Gmail's native collapsible format
  if (thread) {
    const quotedContent = getQuotedContent(thread)
    if (quotedContent.html) {
      // For HTML content, wrap it directly in blockquote without converting to text
      message.push(`  <blockquote class="gmail_quote" style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;">
    ${quotedContent.html}
  </blockquote>`)
      logToFile('constructRawMessage_quoted_content_html', { htmlQuotedLength: quotedContent.html.length })
    } else if (quotedContent.text) {
      // Fallback to text content if no HTML is available
      message.push(`  <blockquote class="gmail_quote" style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;">
    ${quotedContent.text
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/\n/g, '<br>')}
  </blockquote>`)
      logToFile('constructRawMessage_quoted_content_text_fallback', { textQuotedLength: quotedContent.text.length })
    }
  }

  const htmlClosing = '</body></html>'
  message.push(wrapTextBody(htmlClosing))

  // Close the multipart message
  message.push('')
  message.push(`--${boundary}--`)

  const fullMessage = message.join('\r\n')
  const raw = Buffer.from(fullMessage).toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  
  logToFile('constructRawMessage_complete', {
    rawLength: raw.length,
    messagePartsCount: message.length,
    validThreadId,
    // Log a portion of the HTML part for debugging
    htmlPart: fullMessage.substring(
      fullMessage.indexOf('Content-Type: text/html'),
      fullMessage.indexOf('Content-Type: text/html') + 500
    )
  })

  return { raw, validThreadId }
}

function createServer({ config }: { config?: Record<string, any> }) {
  const server = new McpServer({
    name: "Gmail-MCP",
    version: "1.5.1",
    description: "Gmail MCP - Provides complete Gmail API access with file-based OAuth2 authentication"
  })

  server.tool("create_draft",
    "Create a draft email in Gmail.",
    {
      threadId: z.string().optional().describe("The thread ID to associate this draft with"),
      to: z.array(z.string()).optional().describe("List of recipient email addresses"),
      cc: z.array(z.string()).optional().describe("List of CC recipient email addresses"),
      bcc: z.array(z.string()).optional().describe("List of BCC recipient email addresses"),
      subject: z.string().optional().describe("The subject of the email"),
      body: z.string().optional().describe("The body of the email")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        // Log the create_draft request
        logToFile('create_draft', {
          threadId: params.threadId,
          to: params.to,
          cc: params.cc,
          bcc: params.bcc,
          subject: params.subject,
          body: params.body ? params.body.substring(0, 100) + (params.body.length > 100 ? '...' : '') : undefined
        })

        const { raw, validThreadId } = await constructRawMessage(gmail, params)

        const draftCreateParams: DraftCreateParams = { userId: 'me', requestBody: { message: { raw } } }
        // Only set threadId if the thread was successfully validated
        if (validThreadId && draftCreateParams.requestBody?.message) {
          draftCreateParams.requestBody.message.threadId = validThreadId
        }

        const { data } = await gmail.users.drafts.create(draftCreateParams)

        if (data.message?.payload) {
          data.message.payload = processMessagePart(data.message.payload)
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("delete_draft",
    "Delete a draft",
    {
      id: z.string().describe("The ID of the draft to delete")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.drafts.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_draft",
    "Get a specific draft by ID",
    {
      id: z.string().describe("The ID of the draft to retrieve")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.drafts.get({ userId: 'me', id: params.id, format: 'full' })

        if (data.message?.payload) {
          data.message.payload = processMessagePart(data.message.payload)
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("list_drafts",
    "List drafts in the user's mailbox",
    {
      maxResults: z.number().optional().describe("Maximum number of drafts to return. Accepts values between 1-500"),
      q: z.string().optional().describe("Only return drafts matching the specified query. Supports the same query format as the Gmail search box"),
      includeSpamTrash: z.boolean().optional().describe("Include drafts from SPAM and TRASH in the results")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        let drafts: Draft[] = []

        const { data } = await gmail.users.drafts.list({ userId: 'me', ...params })

        drafts.push(...data.drafts || [])

        while (data.nextPageToken) {
          const { data: nextData } = await gmail.users.drafts.list({ userId: 'me', ...params, pageToken: data.nextPageToken })
          drafts.push(...nextData.drafts || [])
        }

        if (drafts) {
          drafts = drafts.map(draft => {
            if (draft.message?.payload) {
              draft.message.payload = processMessagePart(draft.message.payload)
            }
            return draft
          })
        }

        return formatResponse(drafts)
      })
    }
  )

  server.tool("send_draft",
    "Send an existing draft",
    {
      id: z.string().describe("The ID of the draft to send")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        try {
          const { data } = await gmail.users.drafts.send({ userId: 'me', requestBody: { id: params.id } })
          return formatResponse(data)
        } catch (error) {
          return formatResponse({ error: 'Error sending draft, are you sure you have at least one recipient?' })
        }
      })
    }
  )

  // TODO debug issue with subject not being applied correctly
  // server.tool("update_draft",
  //   "Replace a draft's content. Note the mechanics of the threadId and raw parameters.",
  //   {
  //     id: z.string().describe("The ID of the draft to update"),
  //     threadId: z.string().optional().describe("The thread ID to associate this draft with, will be copied from the current draft if not provided"),
  //     raw: z.string().optional().describe("The entire email message in base64url encoded RFC 2822 format, ignores params.to, cc, bcc, subject, body, includeBodyHtml if provided"),
  //     to: z.array(z.string()).optional().describe("List of recipient email addresses, will be copied from the current draft if not provided"),
  //     cc: z.array(z.string()).optional().describe("List of CC recipient email addresses, will be copied from the current draft if not provided"),
  //     bcc: z.array(z.string()).optional().describe("List of BCC recipient email addresses, will be copied from the current draft if not provided"),
  //     subject: z.string().optional().describe("The subject of the email, will be copied from the current draft if not provided"),
  //     body: z.string().optional().describe("The body of the email, will be copied from the current draft if not provided"),
  //     includeBodyHtml: z.boolean().optional().describe("Whether to include the parsed HTML in the return for each body, excluded by default because they can be excessively large")
  //   },
  //   async (params) => {
  //     return handleTool(config, async (gmail: gmail_v1.Gmail) => {
  //       let raw = params.raw
  //       const currentDraft = await gmail.users.drafts.get({ userId: 'me', id: params.id, format: 'full' })
  //       const { payload } = currentDraft.data.message ?? {}

  //       if (currentDraft.data.message?.threadId && !params.threadId) params.threadId = currentDraft.data.message.threadId
  //       if (!params.to) params.to = formatEmailList(findHeader(payload?.headers || [], 'to'))
  //       if (!params.cc) params.cc = formatEmailList(findHeader(payload?.headers || [], 'cc'))
  //       if (!params.bcc) params.bcc = formatEmailList(findHeader(payload?.headers || [], 'bcc'))
  //       if (!params.subject) params.subject = findHeader(payload?.headers || [], 'subject')
  //       if (!params.body) params.body = payload?.parts?.find(p => p.mimeType === 'text/plain')?.body?.data ?? undefined

  //       if (!raw) raw = await constructRawMessage(gmail, params)

  //       const draftUpdateParams: DraftUpdateParams = { userId: 'me', id: params.id, requestBody: { message: { raw, id: params.id } } }
  //       if (params.threadId && draftUpdateParams.requestBody?.message) {
  //         draftUpdateParams.requestBody.message.threadId = params.threadId
  //       }

  //       const { data } = await gmail.users.drafts.update(draftUpdateParams)

  //       if (data.message?.payload) {
  //         data.message.payload = processMessagePart(
  //           data.message.payload,
  //           params.includeBodyHtml
  //         )
  //       }

  //       return formatResponse(data)
  //     })
  //   }
  // )

  server.tool("create_label",
    "Create a new label",
    {
      name: z.string().describe("The display name of the label"),
      messageListVisibility: z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
      labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
      color: z.object({
        textColor: z.string().describe("The text color of the label as hex string"),
        backgroundColor: z.string().describe("The background color of the label as hex string")
      }).optional().describe("The color settings for the label")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.create({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("delete_label",
    "Delete a label",
    {
      id: z.string().describe("The ID of the label to delete")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_label",
    "Get a specific label by ID",
    {
      id: z.string().describe("The ID of the label to retrieve")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.get({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_labels",
    "List all labels in the user's mailbox",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.list({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("patch_label",
    "Patch an existing label (partial update)",
    {
      id: z.string().describe("The ID of the label to patch"),
      name: z.string().optional().describe("The display name of the label"),
      messageListVisibility: z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
      labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
      color: z.object({
        textColor: z.string().describe("The text color of the label as hex string"),
        backgroundColor: z.string().describe("The background color of the label as hex string")
      }).optional().describe("The color settings for the label")
    },
    async (params) => {
      const { id, ...labelData } = params
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.patch({ userId: 'me', id, requestBody: labelData })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_label",
    "Update an existing label",
    {
      id: z.string().describe("The ID of the label to update"),
      name: z.string().optional().describe("The display name of the label"),
      messageListVisibility: z.enum(['show', 'hide']).optional().describe("The visibility of messages with this label in the message list"),
      labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("The visibility of the label in the label list"),
      color: z.object({
        textColor: z.string().describe("The text color of the label as hex string"),
        backgroundColor: z.string().describe("The background color of the label as hex string")
      }).optional().describe("The color settings for the label")
    },
    async (params) => {
      const { id, ...labelData } = params
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.labels.update({ userId: 'me', id, requestBody: labelData })
        return formatResponse(data)
      })
    }
  )

  server.tool("batch_delete_messages",
    "Delete multiple messages",
    {
      ids: z.array(z.string()).describe("The IDs of the messages to delete")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.batchDelete({ userId: 'me', requestBody: { ids: params.ids } })
        return formatResponse(data)
      })
    }
  )

  server.tool("batch_modify_messages",
    "Modify the labels on multiple messages",
    {
      ids: z.array(z.string()).describe("The IDs of the messages to modify"),
      addLabelIds: z.array(z.string()).optional().describe("A list of label IDs to add to the messages"),
      removeLabelIds: z.array(z.string()).optional().describe("A list of label IDs to remove from the messages")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.batchModify({ userId: 'me', requestBody: { ids: params.ids, addLabelIds: params.addLabelIds, removeLabelIds: params.removeLabelIds } })
        return formatResponse(data)
      })
    }
  )

  server.tool("delete_message",
    "Immediately and permanently delete a message",
    {
      id: z.string().describe("The ID of the message to delete")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_message",
    "Get a specific message by ID with format options",
    {
      id: z.string().describe("The ID of the message to retrieve")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.get({ userId: 'me', id: params.id, format: 'full' })

        if (data.payload) {
          data.payload = processMessagePart(data.payload)
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("list_messages",
    "List messages in the user's mailbox with optional filtering",
    {
      maxResults: z.number().optional().describe("Maximum number of messages to return. Accepts values between 1-500"),
      pageToken: z.string().optional().describe("Page token to retrieve a specific page of results"),
      q: z.string().optional().describe("Only return messages matching the specified query. Supports the same query format as the Gmail search box"),
      labelIds: z.array(z.string()).optional().describe("Only return messages with labels that match all of the specified label IDs"),
      includeSpamTrash: z.boolean().optional().describe("Include messages from SPAM and TRASH in the results")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.list({ userId: 'me', ...params })

        if (data.messages) {
          data.messages = data.messages.map((message: Message) => {
            if (message.payload) {
              message.payload = processMessagePart(message.payload)
            }
            return message
          })
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("modify_message",
    "Modify the labels on a message",
    {
      id: z.string().describe("The ID of the message to modify"),
      addLabelIds: z.array(z.string()).optional().describe("A list of label IDs to add to the message"),
      removeLabelIds: z.array(z.string()).optional().describe("A list of label IDs to remove from the message")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.modify({ userId: 'me', id: params.id, requestBody: { addLabelIds: params.addLabelIds, removeLabelIds: params.removeLabelIds } })
        return formatResponse(data)
      })
    }
  )

  server.tool("send_message",
    "Send an email message to specified recipients.",
    {
      threadId: z.string().optional().describe("The thread ID to associate this message with"),
      to: z.array(z.string()).optional().describe("List of recipient email addresses"),
      cc: z.array(z.string()).optional().describe("List of CC recipient email addresses"),
      bcc: z.array(z.string()).optional().describe("List of BCC recipient email addresses"),
      subject: z.string().optional().describe("The subject of the email"),
      body: z.string().optional().describe("The body of the email")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        // Log the send_message request
        logToFile('send_message', {
          threadId: params.threadId,
          to: params.to,
          cc: params.cc,
          bcc: params.bcc,
          subject: params.subject,
          body: params.body ? params.body.substring(0, 100) + (params.body.length > 100 ? '...' : '') : undefined
        })

        const { raw, validThreadId } = await constructRawMessage(gmail, params)

        const messageSendParams: MessageSendParams = { userId: 'me', requestBody: { raw } }
        // Only set threadId if the thread was successfully validated
        if (validThreadId && messageSendParams.requestBody) {
          messageSendParams.requestBody.threadId = validThreadId
        }

        const { data } = await gmail.users.messages.send(messageSendParams)

        if (data.payload) {
          data.payload = processMessagePart(data.payload)
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("trash_message",
    "Move a message to the trash",
    {
      id: z.string().describe("The ID of the message to move to trash")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.trash({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("untrash_message",
    "Remove a message from the trash",
    {
      id: z.string().describe("The ID of the message to remove from trash")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.untrash({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_attachment",
    "Get a message attachment",
    {
      messageId: z.string().describe("ID of the message containing the attachment"),
      id: z.string().describe("The ID of the attachment"),
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.messages.attachments.get({ userId: 'me', messageId: params.messageId, id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("delete_thread",
    "Delete a thread",
    {
      id: z.string().describe("The ID of the thread to delete")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_thread",
    "Get a specific thread by ID",
    {
      id: z.string().describe("The ID of the thread to retrieve")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.get({ userId: 'me', id: params.id, format: 'full' })

        if (data.messages) {
          data.messages = data.messages.map(message => {
            if (message.payload) {
              message.payload = processMessagePart(message.payload)
            }
            return message
          })
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("list_threads",
    "List threads in the user's mailbox",
    {
      maxResults: z.number().optional().describe("Maximum number of threads to return"),
      pageToken: z.string().optional().describe("Page token to retrieve a specific page of results"),
      q: z.string().optional().describe("Only return threads matching the specified query"),
      labelIds: z.array(z.string()).optional().describe("Only return threads with labels that match all of the specified label IDs"),
      includeSpamTrash: z.boolean().optional().describe("Include threads from SPAM and TRASH in the results")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.list({ userId: 'me', ...params })
        console.log(data)

        if (data.threads) {
          data.threads = data.threads.map(thread => {
            if (thread.messages) {
              thread.messages = thread.messages.map(message => {
                if (message.payload) {
                  message.payload = processMessagePart(message.payload)
                }
                return message
              })
            }
            return thread
          })
        }

        return formatResponse(data)
      })
    }
  )

  server.tool("modify_thread",
    "Modify the labels applied to a thread",
    {
      id: z.string().describe("The ID of the thread to modify"),
      addLabelIds: z.array(z.string()).optional().describe("A list of label IDs to add to the thread"),
      removeLabelIds: z.array(z.string()).optional().describe("A list of label IDs to remove from the thread")
    },
    async (params) => {
      const { id, ...threadData } = params
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.modify({ userId: 'me', id, requestBody: threadData })
        return formatResponse(data)
      })
    }
  )

  server.tool("trash_thread",
    "Move a thread to the trash",
    {
      id: z.string().describe("The ID of the thread to move to trash")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.trash({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("untrash_thread",
    "Remove a thread from the trash",
    {
      id: z.string().describe("The ID of the thread to remove from trash")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.threads.untrash({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_auto_forwarding",
    "Gets auto-forwarding settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getAutoForwarding({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_imap",
    "Gets IMAP settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getImap({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_language",
    "Gets language settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getLanguage({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_pop",
    "Gets POP settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getPop({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_vacation",
    "Get vacation responder settings",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.getVacation({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_auto_forwarding",
    "Updates automatic forwarding settings",
    {
      enabled: z.boolean().describe("Whether all incoming mail is automatically forwarded to another address"),
      emailAddress: z.string().describe("Email address to which messages should be automatically forwarded"),
      disposition: z.enum(['leaveInInbox', 'archive', 'trash', 'markRead']).describe("The state in which messages should be left after being forwarded")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateAutoForwarding({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_imap",
    "Updates IMAP settings",
    {
      enabled: z.boolean().describe("Whether IMAP is enabled for the account"),
      expungeBehavior: z.enum(['archive', 'trash', 'deleteForever']).optional().describe("The action that will be executed on a message when it is marked as deleted and expunged from the last visible IMAP folder"),
      maxFolderSize: z.number().optional().describe("An optional limit on the number of messages that can be accessed through IMAP")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateImap({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_language",
    "Updates language settings",
    {
      displayLanguage: z.string().describe("The language to display Gmail in, formatted as an RFC 3066 Language Tag")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateLanguage({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_pop",
    "Updates POP settings",
    {
      accessWindow: z.enum(['disabled', 'allMail', 'fromNowOn']).describe("The range of messages which are accessible via POP"),
      disposition: z.enum(['archive', 'trash', 'leaveInInbox']).describe("The action that will be executed on a message after it has been fetched via POP")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updatePop({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_vacation",
    "Update vacation responder settings",
    {
      enableAutoReply: z.boolean().describe("Whether the vacation responder is enabled"),
      responseSubject: z.string().optional().describe("Optional subject line for the vacation responder auto-reply"),
      responseBodyPlainText: z.string().describe("Response body in plain text format"),
      restrictToContacts: z.boolean().optional().describe("Whether responses are only sent to contacts"),
      restrictToDomain: z.boolean().optional().describe("Whether responses are only sent to users in the same domain"),
      startTime: z.string().optional().describe("Start time for sending auto-replies (epoch ms)"),
      endTime: z.string().optional().describe("End time for sending auto-replies (epoch ms)")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.updateVacation({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("add_delegate",
    "Adds a delegate to the specified account",
    {
      delegateEmail: z.string().describe("Email address of delegate to add")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.create({ userId: 'me', requestBody: { delegateEmail: params.delegateEmail } })
        return formatResponse(data)
      })
    }
  )

  server.tool("remove_delegate",
    "Removes the specified delegate",
    {
      delegateEmail: z.string().describe("Email address of delegate to remove")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.delete({ userId: 'me', delegateEmail: params.delegateEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_delegate",
    "Gets the specified delegate",
    {
      delegateEmail: z.string().describe("The email address of the delegate to retrieve")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.get({ userId: 'me', delegateEmail: params.delegateEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_delegates",
    "Lists the delegates for the specified account",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.delegates.list({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("create_filter",
    "Creates a filter",
    {
      criteria: z.object({
        from: z.string().optional().describe("The sender's display name or email address"),
        to: z.string().optional().describe("The recipient's display name or email address"),
        subject: z.string().optional().describe("Case-insensitive phrase in the message's subject"),
        query: z.string().optional().describe("A Gmail search query that specifies the filter's criteria"),
        negatedQuery: z.string().optional().describe("A Gmail search query that specifies criteria the message must not match"),
        hasAttachment: z.boolean().optional().describe("Whether the message has any attachment"),
        excludeChats: z.boolean().optional().describe("Whether the response should exclude chats"),
        size: z.number().optional().describe("The size of the entire RFC822 message in bytes"),
        sizeComparison: z.enum(['smaller', 'larger']).optional().describe("How the message size in bytes should be in relation to the size field")
      }).describe("Filter criteria"),
      action: z.object({
        addLabelIds: z.array(z.string()).optional().describe("List of labels to add to messages"),
        removeLabelIds: z.array(z.string()).optional().describe("List of labels to remove from messages"),
        forward: z.string().optional().describe("Email address that the message should be forwarded to")
      }).describe("Actions to perform on messages matching the criteria")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.create({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("delete_filter",
    "Deletes a filter",
    {
      id: z.string().describe("The ID of the filter to be deleted")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.delete({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_filter",
    "Gets a filter",
    {
      id: z.string().describe("The ID of the filter to be fetched")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.get({ userId: 'me', id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_filters",
    "Lists the message filters of a Gmail user",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.filters.list({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("create_forwarding_address",
    "Creates a forwarding address",
    {
      forwardingEmail: z.string().describe("An email address to which messages can be forwarded")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.create({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("delete_forwarding_address",
    "Deletes the specified forwarding address",
    {
      forwardingEmail: z.string().describe("The forwarding address to be deleted")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.delete({ userId: 'me', forwardingEmail: params.forwardingEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_forwarding_address",
    "Gets the specified forwarding address",
    {
      forwardingEmail: z.string().describe("The forwarding address to be retrieved")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.get({ userId: 'me', forwardingEmail: params.forwardingEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_forwarding_addresses",
    "Lists the forwarding addresses for the specified account",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.forwardingAddresses.list({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("create_send_as",
    "Creates a custom send-as alias",
    {
      sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
      displayName: z.string().optional().describe("A name that appears in the 'From:' header"),
      replyToAddress: z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
      signature: z.string().optional().describe("An optional HTML signature"),
      isPrimary: z.boolean().optional().describe("Whether this address is the primary address"),
      treatAsAlias: z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.create({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("delete_send_as",
    "Deletes the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The send-as alias to be deleted")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.delete({ userId: 'me', sendAsEmail: params.sendAsEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_send_as",
    "Gets the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The send-as alias to be retrieved")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.get({ userId: 'me', sendAsEmail: params.sendAsEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_send_as",
    "Lists the send-as aliases for the specified account",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.list({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("patch_send_as",
    "Patches the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The send-as alias to be updated"),
      displayName: z.string().optional().describe("A name that appears in the 'From:' header"),
      replyToAddress: z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
      signature: z.string().optional().describe("An optional HTML signature"),
      isPrimary: z.boolean().optional().describe("Whether this address is the primary address"),
      treatAsAlias: z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
    },
    async (params) => {
      const { sendAsEmail, ...patchData } = params
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.patch({ userId: 'me', sendAsEmail, requestBody: patchData })
        return formatResponse(data)
      })
    }
  )

  server.tool("update_send_as",
    "Updates a send-as alias",
    {
      sendAsEmail: z.string().describe("The send-as alias to be updated"),
      displayName: z.string().optional().describe("A name that appears in the 'From:' header"),
      replyToAddress: z.string().optional().describe("An optional email address that is included in a 'Reply-To:' header"),
      signature: z.string().optional().describe("An optional HTML signature"),
      isPrimary: z.boolean().optional().describe("Whether this address is the primary address"),
      treatAsAlias: z.boolean().optional().describe("Whether Gmail should treat this address as an alias")
    },
    async (params) => {
      const { sendAsEmail, ...updateData } = params
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.update({ userId: 'me', sendAsEmail, requestBody: updateData })
        return formatResponse(data)
      })
    }
  )

  server.tool("verify_send_as",
    "Sends a verification email to the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The send-as alias to be verified")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.verify({ userId: 'me', sendAsEmail: params.sendAsEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("delete_smime_info",
    "Deletes the specified S/MIME config for the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
      id: z.string().describe("The immutable ID for the S/MIME config")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.delete({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_smime_info",
    "Gets the specified S/MIME config for the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
      id: z.string().describe("The immutable ID for the S/MIME config")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.get({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("insert_smime_info",
    "Insert (upload) the given S/MIME config for the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
      encryptedKeyPassword: z.string().describe("Encrypted key password"),
      pkcs12: z.string().describe("PKCS#12 format containing a single private/public key pair and certificate chain")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.insert({ userId: 'me', sendAsEmail: params.sendAsEmail, requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("list_smime_info",
    "Lists S/MIME configs for the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The email address that appears in the 'From:' header")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.list({ userId: 'me', sendAsEmail: params.sendAsEmail })
        return formatResponse(data)
      })
    }
  )

  server.tool("set_default_smime_info",
    "Sets the default S/MIME config for the specified send-as alias",
    {
      sendAsEmail: z.string().describe("The email address that appears in the 'From:' header"),
      id: z.string().describe("The immutable ID for the S/MIME config")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.settings.sendAs.smimeInfo.setDefault({ userId: 'me', sendAsEmail: params.sendAsEmail, id: params.id })
        return formatResponse(data)
      })
    }
  )

  server.tool("get_profile",
    "Get the current user's Gmail profile",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.getProfile({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  server.tool("watch_mailbox",
    "Watch for changes to the user's mailbox",
    {
      topicName: z.string().describe("The name of the Cloud Pub/Sub topic to publish notifications to"),
      labelIds: z.array(z.string()).optional().describe("Label IDs to restrict notifications to"),
      labelFilterAction: z.enum(['include', 'exclude']).optional().describe("Whether to include or exclude the specified labels")
    },
    async (params) => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.watch({ userId: 'me', requestBody: params })
        return formatResponse(data)
      })
    }
  )

  server.tool("stop_mail_watch",
    "Stop receiving push notifications for the given user mailbox",
    {},
    async () => {
      return handleTool(config, async (gmail: gmail_v1.Gmail) => {
        const { data } = await gmail.users.stop({ userId: 'me' })
        return formatResponse(data)
      })
    }
  )

  return server.server
}

const main = async () => {
  fs.mkdirSync(MCP_CONFIG_DIR, { recursive: true })

  if (process.argv[2] === 'auth') {
    if (!defaultOAuth2Client) throw new Error('OAuth2 client could not be created, please check your credentials')
    await launchAuthServer(defaultOAuth2Client)
    process.exit(0)
  }

  // Stdio Server
  const stdioServer = createServer({})
  const transport = new StdioServerTransport()
  await stdioServer.connect(transport)
}

main()
