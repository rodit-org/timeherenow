#!/usr/bin/env node
/**
 * Debug script to test /api/sessions/revoke endpoint
 * This helps diagnose the 403 Permission Denied error
 */

const axios = require('axios');

// Configuration
const API_ENDPOINT = process.env.API_ENDPOINT || 'https://api.timeherenow.com';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN; // JWT token from login
const SESSION_ID = process.env.SESSION_ID || 'test-session-id';

async function testRevokeEndpoint() {
  console.log('=== Testing /api/sessions/revoke Endpoint ===\n');
  console.log(`API Endpoint: ${API_ENDPOINT}`);
  console.log(`Session ID: ${SESSION_ID}`);
  console.log(`Admin Token: ${ADMIN_TOKEN ? ADMIN_TOKEN.substring(0, 50) + '...' : 'NOT SET'}\n`);

  if (!ADMIN_TOKEN) {
    console.error('❌ ERROR: ADMIN_TOKEN environment variable not set');
    console.error('Usage: ADMIN_TOKEN=<jwt> SESSION_ID=<id> node debug-revoke-test.js');
    process.exit(1);
  }

  try {
    // Test 1: Check token structure
    console.log('--- Test 1: Decode JWT Token ---');
    const tokenParts = ADMIN_TOKEN.split('.');
    if (tokenParts.length === 3) {
      const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
      console.log('Token Subject:', payload.sub);
      console.log('Token Expiry:', new Date(payload.exp * 1000).toISOString());
      
      // Check permissioned routes
      let permissionedRoutes;
      if (typeof payload.rodit_permissionedroutes === 'string') {
        permissionedRoutes = JSON.parse(payload.rodit_permissionedroutes);
      } else {
        permissionedRoutes = payload.rodit_permissionedroutes;
      }
      
      const methods = permissionedRoutes?.entities?.methods || {};
      const hasRevokePermission = methods['/api/sessions/revoke'];
      
      console.log('Has /api/sessions/revoke permission:', hasRevokePermission || 'NO');
      console.log('Available session routes:');
      Object.keys(methods).filter(k => k.includes('/sessions')).forEach(route => {
        console.log(`  - ${route}: ${methods[route]}`);
      });
      console.log('✅ Token decoded successfully\n');
    } else {
      console.error('❌ Invalid JWT token format\n');
    }

    // Test 2: Call the revoke endpoint
    console.log('--- Test 2: Call /api/sessions/revoke ---');
    const response = await axios.post(
      `${API_ENDPOINT}/api/sessions/revoke`,
      {
        sessionId: SESSION_ID,
        reason: 'debug_test'
      },
      {
        headers: {
          'Authorization': ADMIN_TOKEN,
          'Content-Type': 'application/json'
        },
        validateStatus: () => true // Don't throw on any status
      }
    );

    console.log('Response Status:', response.status);
    console.log('Response Body:', JSON.stringify(response.data, null, 2));

    if (response.status === 200) {
      console.log('\n✅ SUCCESS: Session revoked successfully');
    } else if (response.status === 403) {
      console.log('\n❌ FAILED: 403 Permission Denied');
      console.log('This means the route is NOT in your token\'s permissioned_routes');
      console.log('or the path doesn\'t match exactly.');
    } else if (response.status === 404) {
      console.log('\n⚠️  Session not found (but authorization worked!)');
    } else {
      console.log(`\n❌ FAILED: Unexpected status ${response.status}`);
    }

  } catch (error) {
    console.error('\n❌ ERROR:', error.message);
    if (error.response) {
      console.error('Response Status:', error.response.status);
      console.error('Response Body:', error.response.data);
    }
  }
}

testRevokeEndpoint();
