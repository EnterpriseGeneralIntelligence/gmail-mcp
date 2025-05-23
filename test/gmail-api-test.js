#!/usr/bin/env node

import { google } from 'googleapis';
import { createOAuth2Client, validateCredentials } from '../dist/oauth2.js';

async function testGmailAPI() {
  try {
    console.log('Testing Gmail API connection...');

    // Create OAuth2 client using the environment variables
    const oauth2Client = createOAuth2Client();
    if (!oauth2Client) {
      throw new Error('OAuth2 client could not be created, please check your credentials');
    }

    // Validate credentials
    const credentialsAreValid = await validateCredentials(oauth2Client);
    if (!credentialsAreValid) {
      throw new Error('OAuth2 credentials are invalid, please re-authenticate');
    }

    console.log('OAuth2 credentials are valid!');

    // Create Gmail client
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Test API by getting user profile
    const { data: profile } = await gmail.users.getProfile({ userId: 'me' });
    console.log('Successfully connected to Gmail API!');
    console.log('User profile:', profile);

    // List the last 5 messages
    const { data: messages } = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 5
    });

    console.log(`\nFound ${messages.messages?.length || 0} messages`);

    // Get details of the first message
    if (messages.messages && messages.messages.length > 0) {
      const firstMessageId = messages.messages[0].id;
      const { data: messageDetails } = await gmail.users.messages.get({
        userId: 'me',
        id: firstMessageId,
        format: 'metadata'
      });

      console.log('\nFirst message details:');
      if (messageDetails.payload?.headers) {
        const subject = messageDetails.payload.headers.find(h => h.name === 'Subject')?.value;
        const from = messageDetails.payload.headers.find(h => h.name === 'From')?.value;
        console.log(`From: ${from || 'Unknown'}`);
        console.log(`Subject: ${subject || 'No subject'}`);
      }
    }

    // List labels
    const { data: labels } = await gmail.users.labels.list({ userId: 'me' });
    console.log(`\nFound ${labels.labels?.length || 0} labels`);
    if (labels.labels) {
      console.log('Labels:', labels.labels.map(label => label.name).join(', '));
    }

  } catch (error) {
    console.error('Error testing Gmail API:', error.message);
    if (error.response) {
      console.error('Response error data:', error.response.data);
    }
  }
}

testGmailAPI();
