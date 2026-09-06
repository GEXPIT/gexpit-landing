/**
 * ============================================================================
 * GEXPIT INSTITUTIONAL PLATFORM — GOOGLE APPS SCRIPT (STORAGE VAULT)
 * Version: 2.1.0 (Hardened Vault Blueprint + CSV Injection Armor + Jitter Lock Retry)
 * Deployment: Web App (Execute as: Me, Who has access: Anyone)
 * ============================================================================
 */

// RFC 5322 Compliant Email Regex Validator (Secondary Defense-in-Depth)
var EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

/**
 * Constant-time string comparison to neutralize timing attack side-channels.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeTokenCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  var lenA = a.length;
  var lenB = b.length;
  var mismatch = lenA ^ lenB;
  for (var i = 0; i < Math.max(lenA, lenB); i++) {
    var charA = i < lenA ? a.charCodeAt(i) : 0;
    var charB = i < lenB ? b.charCodeAt(i) : 0;
    mismatch |= (charA ^ charB);
  }
  return mismatch === 0;
}

/**
 * Sanitizes input cells to neutralize Formula / CSV Injection (DDE, Hyperlinks, Control Chars).
 * Strips all ASCII control characters, newlines, tabs, and invisible zero-width Unicode characters.
 * Ensures untrusted text starting with formula triggers is escaped with a single quote.
 * @param {*} val Raw input value.
 * @param {number} maxLen Maximum permissible character length.
 * @returns {string} Sanitized text string.
 */
function sanitizeCellValue(val, maxLen) {
  if (val === null || val === undefined) return "N/A";
  var str = String(val);
  // Strip all ASCII control characters (\x00-\x1F, \x7F) including \r and \n to prevent CSV line splitting
  str = str.replace(/[\x00-\x1F\x7F]/g, "");
  // Strip all leading and trailing ASCII/Unicode whitespace and invisible zero-width characters (e.g. \u200B, \u200C, \u200D, \uFEFF, \u00A0)
  str = str.replace(/^[\s\u200B-\u200D\uFEFF\u00A0]+|[\s\u200B-\u200D\uFEFF\u00A0]+$/g, "");
  if (maxLen && str.length > maxLen) {
    str = str.substring(0, maxLen);
  }
  // Neutralize spreadsheet formula execution triggers (ASCII & Unicode Full-width variants)
  if (/^[=+\-@\t\r\n\|%\uFF1D\uFF0B\uFF0D\uFF20]/.test(str)) {
    return "'" + str;
  }
  return str;
}

/**
 * HTTP POST Request Handler
 * Intercepts forwarded telemetry from Cloudflare Worker and appends to Sheet.
 * @param {object} e Event parameter containing HTTP postData.
 * @returns {TextOutput} JSON response payload.
 */
function doPost(e) {
  // 1. Validate Input Payload (Fast-Fail outside lock)
  if (!e || !e.postData || !e.postData.contents) {
    return ContentService.createTextOutput(JSON.stringify({
      "status": "error",
      "message": "Malformed request. Missing postData body."
    })).setMimeType(ContentService.MimeType.JSON);
  }

  // 2. Parse Incoming JSON (Fast-Fail outside lock)
  var data;
  try {
    data = JSON.parse(e.postData.contents);
  } catch (jsonErr) {
    return ContentService.createTextOutput(JSON.stringify({
      "status": "error",
      "message": "Invalid JSON format in postData body."
    })).setMimeType(ContentService.MimeType.JSON);
  }

  // 3. Vault Access Control & Authentication Shield (Fast-Fail outside lock)
  var expectedVaultToken = "";
  try {
    expectedVaultToken = PropertiesService.getScriptProperties().getProperty("VAULT_SECRET_TOKEN") || "";
  } catch (propErr) {
    console.error("[GEXPIT VAULT] Failed to access ScriptProperties:", propErr);
  }

  if (!expectedVaultToken) {
    return ContentService.createTextOutput(JSON.stringify({
      "status": "error",
      "message": "Vault configuration error: VAULT_SECRET_TOKEN is not configured in Script Properties."
    })).setMimeType(ContentService.MimeType.JSON);
  }

  var incomingVaultToken = (data && data.vaultToken) ? String(data.vaultToken) : "";
  if (!safeTokenCompare(incomingVaultToken, expectedVaultToken)) {
    return ContentService.createTextOutput(JSON.stringify({
      "status": "error",
      "message": "Unauthorized: Invalid or missing vault security token."
    })).setMimeType(ContentService.MimeType.JSON);
  }

  // 4. Extract and Sanitize Telemetry Data (Outside lock)
  var email = sanitizeCellValue(data.email, 254);
  if (!EMAIL_REGEX.test(email)) {
    return ContentService.createTextOutput(JSON.stringify({
      "status": "error",
      "message": "Malformed email address. RFC 5322 validation failed."
    })).setMimeType(ContentService.MimeType.JSON);
  }
  var source = sanitizeCellValue(data.source || "web_edge_cockpit", 100);
  var timestamp = sanitizeCellValue(data.timestamp || new Date().toISOString(), 50);
  var clientIp = sanitizeCellValue(data.clientIp || "N/A", 50);
  var submissionDate = new Date();

  // 5. Acquire Scoped Short Lock ONLY for Spreadsheet I/O
  var lock = LockService.getScriptLock();
  var lockAcquired = false;
  try {
    // Wait up to 2500ms for lock (prevents massive request backlog/concurrency queuing)
    lockAcquired = lock.tryLock(2500);
    if (!lockAcquired) {
      // Jitter backoff retry to absorb concurrency peaks across concurrent executions
      Utilities.sleep(100 + Math.floor(Math.random() * 200));
      lockAcquired = lock.tryLock(2000);
    }
  } catch (lockErr) {
    lockAcquired = false;
  }

  if (!lockAcquired) {
    return ContentService.createTextOutput(JSON.stringify({
      "status": "error",
      "message": "Server busy. Storage vault locked by concurrent operations. Please retry."
    })).setMimeType(ContentService.MimeType.JSON);
  }

  try {
    // 6. Target Active Spreadsheet & Sheet
    var spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = spreadsheet.getActiveSheet();

    // Initialize Header Row if empty
    var lastRow = sheet.getLastRow();
    if (lastRow === 0) {
      sheet.appendRow(["Server Timestamp", "Institutional Email", "Form Source", "Client Timestamp", "Client IP"]);
      sheet.getRange("A1:E1").setFontWeight("bold");
      lastRow = 1;
    }

    // 7. Deduplication Shield: High-Performance Native TextFinder Search (O(1) C++ Backend Search)
    if (lastRow > 1) {
      var emailColumn = sheet.getRange(2, 2, lastRow - 1, 1);
      var textFinder = emailColumn.createTextFinder(email).matchEntireCell(true).matchCase(false);
      var existingCell = textFinder.findNext();
      if (existingCell) {
        // Idempotent uniform success response (neutralizes email enumeration probes)
        return ContentService.createTextOutput(JSON.stringify({
          "status": "success",
          "message": "Access request successfully registered.",
          "recordedAt": submissionDate.toISOString()
        })).setMimeType(ContentService.MimeType.JSON);
      }
    }

    // 8. Append Telemetry Row Atomically
    sheet.appendRow([
      submissionDate,
      email,
      source,
      timestamp,
      clientIp
    ]);

    // 9. Return Success JSON Response (Uniform format)
    return ContentService.createTextOutput(JSON.stringify({
      "status": "success",
      "message": "Access request successfully registered.",
      "recordedAt": submissionDate.toISOString()
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    console.error("[GEXPIT VAULT ERROR]", error);
    return ContentService.createTextOutput(JSON.stringify({
      "status": "error",
      "message": "Internal storage vault processing error."
    })).setMimeType(ContentService.MimeType.JSON);

  } finally {
    // Release Lock immediately
    try {
      lock.releaseLock();
    } catch (e) {
      // Non-fatal if already released
    }
  }
}

/**
 * HTTP GET Healthcheck Handler (Neutral status)
 * @param {object} e
 * @returns {TextOutput}
 */
function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    "status": "active"
  })).setMimeType(ContentService.MimeType.JSON);
}
