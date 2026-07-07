"""
ReconMind Phase 3 — Architecture Redesign Master Document
==========================================================
Author: wamiqsec
Topic:  Why false positives happen + full intelligent validation redesign

This file is the architectural specification and implementation guide.
Read every section. Every design decision is explained.
"""

# ═══════════════════════════════════════════════════════════════════════════
# PART 1: ROOT CAUSE ANALYSIS — WHY FALSE POSITIVES HAPPEN
# ═══════════════════════════════════════════════════════════════════════════

"""
─────────────────────────────────────────────────────────────────────────────
1.1  THE FUNDAMENTAL LOGICAL ERROR IN DIFF-BASED SCANNING
─────────────────────────────────────────────────────────────────────────────

Current scanner logic (wrong):

    baseline = GET /post?id=1     → response_size = 8420 bytes
    probe    = GET /post?id=2     → response_size = 9100 bytes
    diff     = 680 bytes
    if diff > threshold:
        report_idor()

Why this is wrong:

    /post?id=1 and /post?id=2 are DIFFERENT BLOG POSTS.
    They are supposed to have different content.
    Different content = different size.
    This is NOT a vulnerability. This is the application working correctly.

The logical error:
    The scanner confuses "content changed" with "unauthorized access occurred".
    These are completely different things.

    Content changing = normal for public paginated content
    Unauthorized access = user A reading user B's PRIVATE data

    The scanner has no concept of:
        - Is this endpoint public or protected?
        - Does the application expect different content per ID?
        - Is the returned content actually sensitive?
        - Is there an authorization mechanism being bypassed?


─────────────────────────────────────────────────────────────────────────────
1.2  THE SIX CLASSES OF FALSE POSITIVES WE GENERATE TODAY
─────────────────────────────────────────────────────────────────────────────

CLASS 1: Public Paginated Content (Most Common — 70% of false positives)
    /post?id=1  → blog post 1 (8420 bytes)
    /post?id=2  → blog post 2 (9100 bytes)
    DIFF: 680 bytes → we report IDOR
    REALITY: Public content. No auth bypass. Not a bug.

CLASS 2: Dynamic Timestamps / Session Data
    /dashboard?tab=1  → contains "Last login: 14:23:01"
    Re-request same URL  → "Last login: 14:23:07"
    DIFF: timestamp changed → we might report false reflection
    REALITY: Server generates dynamic content. Normal behavior.

CLASS 3: CSRF Tokens in Responses
    /page?id=1  → contains <input name="csrf" value="abc123">
    /page?id=2  → contains <input name="csrf" value="def456">
    DIFF: different CSRF token → size difference
    REALITY: CSRF tokens are supposed to change. Not a bug.

CLASS 4: Ads / Analytics / CDN Content
    /article?id=1  → ad slot renders ad A (200 bytes)
    /article?id=2  → ad slot renders ad B (350 bytes)
    DIFF: 150 bytes → we report IDOR
    REALITY: Ad network returned different content. Nothing to do with auth.

CLASS 5: Server-Side Caching Effects
    /api/item?id=5  → cached response (fast, 200 bytes headers)
    /api/item?id=6  → cache miss (slower, more headers)
    DIFF: header size/timing differs → we report SSRF time-based
    REALITY: CDN cache behavior. Not SSRF.

CLASS 6: Reflected Parameter in Error Messages
    /search?q=hello  → "No results for 'hello'"
    XSS test: /search?q=XSS123TEST  → "No results for 'XSS123TEST'"
    We detect reflection → report XSS candidate
    But: the reflection is inside a plain text <p> tag, fully encoded.
    REALITY: Encoded reflection in body. Not exploitable without context.


─────────────────────────────────────────────────────────────────────────────
1.3  WHY THE CURRENT IDOR LOGIC IS ARCHITECTURALLY WRONG
─────────────────────────────────────────────────────────────────────────────

Current IDOR logic asks:
    "Did the response change when I changed the ID?"

Correct IDOR logic asks:
    "Did the server return data belonging to a DIFFERENT AUTHORIZED ENTITY
     without verifying that I have permission to access that entity?"

These are fundamentally different questions.

The current logic cannot answer the correct question because:

    1. It has no concept of authentication context
       → It doesn't know if the request is even authenticated
       → Without auth, changing id=1 to id=2 on a public blog is expected

    2. It has no concept of data ownership
       → It can't distinguish "public content that changes per ID"
         from "private content that should only be accessed by owner"

    3. It has no behavioral baseline calibration
       → It doesn't test: "what does the server return for a NONEXISTENT id?"
       → If id=99999 returns 404, the endpoint has access control
       → If id=99999 returns a different user's data, that's IDOR

    4. It uses a single-dimension signal (size difference)
       → Size difference on public content = always fires
       → A smarter signal: does the content contain data that belongs to
         a SPECIFIC OTHER USER that our session shouldn't access?

    5. It doesn't test the authorization control directly
       → True IDOR test: with SESSION_A's cookies, request id=SESSION_B_ID
       → Without session cookies: you're testing public access, not IDOR


─────────────────────────────────────────────────────────────────────────────
1.4  WHY SSRF TIME-BASED DETECTION IS UNRELIABLE
─────────────────────────────────────────────────────────────────────────────

Current logic:
    baseline_time = measure(original_request)
    probe_time = measure(request_with_192.0.2.1_injected)
    if probe_time - baseline_time > 2.0:
        report_ssrf()

Problems:

    1. Network jitter is real
       → baseline: 0.8s, probe: 3.1s → delta = 2.3s → we report SSRF
       → But the 3.1s was just network congestion on the probe request
       → A single measurement proves nothing

    2. Server-side timeout varies
       → Some servers have 1s connect timeout, others have 30s
       → A 2s threshold catches 30s-timeout servers but misses 1s ones

    3. The baseline might already be slow
       → If the app server is under load, baseline = 3s
       → Probe = 3.5s → delta = 0.5s → we MISS the SSRF
       → Next request baseline = 0.9s → probe = 3.4s → delta = 2.5s → we REPORT

    4. We only measure once
       → Statistical noise from a single measurement is unacceptable
       → Minimum: 3 baseline measurements, 3 probe measurements
       → Report only if median(probe_times) - median(baseline_times) > threshold


─────────────────────────────────────────────────────────────────────────────
1.5  WHY CURRENT REFLECTION DETECTION CREATES FALSE POSITIVES
─────────────────────────────────────────────────────────────────────────────

Current logic:
    inject marker "XSS123TEST"
    if marker in response:
        reflected = True

Problem 1: Marker was ALREADY in the page
    Some apps include test data, cached content, or user data
    that happens to contain our marker string.
    We don't diff against a pre-injection baseline of the same parameter.

Problem 2: Reflected in a non-injectable context
    <title>Search results for XSS123TEST</title>
    → reflected = True
    But this is inside <title>, not exploitable for JS execution.
    Current context analyzer doesn't correctly handle all title/meta contexts.

Problem 3: Encoding detection is incomplete
    The server might encode with Unicode escaping: \\u003cscript\\u003e
    Or CSS encoding: \\3c script\\3e
    We only check HTML entity encoding, missing other encoding schemes.

Problem 4: Reflection in cached responses
    CDN might cache the previous user's reflected content.
    We might detect another request's reflected data, not our own.
"""


# ═══════════════════════════════════════════════════════════════════════════
# PART 2: HOW PROFESSIONAL SCANNERS WORK
# ═══════════════════════════════════════════════════════════════════════════

"""
─────────────────────────────────────────────────────────────────────────────
2.1  HOW BURP SUITE PRO VALIDATES FINDINGS
─────────────────────────────────────────────────────────────────────────────

Burp Suite Pro (the industry standard) uses these validation techniques:

    XSS Validation:
        - Injects unique probe strings with embedded canary tokens
        - Checks for the canary in different encoding forms
        - Uses multiple reflection points to confirm it's actually injecting
        - For stored XSS: checks a SECOND request (the view URL) for the payload
        - Classifies by context using a full HTML parser, not regex
        - Requires the payload to appear in an EXECUTABLE context
          (not just anywhere in the DOM)

    IDOR/Access Control Validation:
        - Burp doesn't auto-detect IDOR — it requires manual configuration
        - This is intentional: the tool knows it can't distinguish
          public vs private content without human context
        - Burp's Collaborator is used for out-of-band confirmation

    SSRF Validation:
        - Uses Burp Collaborator (an external DNS/HTTP server you control)
        - Injects Collaborator URLs (unique per-request)
        - Confirms SSRF only when Collaborator receives a callback
        - This is OUT-OF-BAND validation — far more reliable than timing

    SQLi Validation:
        - Boolean-based: injects TRUE and FALSE conditions
          and compares responses (not just "response changed")
        - Time-based: repeats the time probe multiple times,
          uses statistical median, not a single measurement
        - Error-based: looks for specific database error strings
          (not just any error)
        - Requires the response difference to be CONSISTENT across
          multiple requests, not just one comparison

─────────────────────────────────────────────────────────────────────────────
2.2  HOW OWASP ZAP VALIDATES FINDINGS
─────────────────────────────────────────────────────────────────────────────

    ZAP uses "Active Scan Rules" — each rule is a mini-validation pipeline:

    1. Strength parameter: how many payloads and variations to try
    2. Threshold parameter: how confident the match must be before reporting

    ZAP's false positive reduction techniques:
        - Anti-CSRF token handling (doesn't inject into CSRF fields)
        - Session management (understands login state)
        - Custom scan policies per application type
        - Alert deduplication (same issue, different URLs = one report)
        - Alert correlation (groups related findings)

─────────────────────────────────────────────────────────────────────────────
2.3  THE CORE PRINCIPLE: LAYERED EVIDENCE
─────────────────────────────────────────────────────────────────────────────

Professional scanners NEVER report on a single signal.
They require MULTIPLE INDEPENDENT SIGNALS to agree before reporting.

For XSS to be reported:
    Signal 1: Marker reflected in response ✓
    Signal 2: Reflection is in executable context (JS/attribute) ✓
    Signal 3: Reflection is NOT encoded ✓
    Signal 4: Second probe with different marker also reflects ✓ (optional)
    → 3/4 signals = report with HIGH confidence

For IDOR to be reported:
    Signal 1: Request with different ID returns different content ✓
    Signal 2: Content contains user-specific data patterns ✓
    Signal 3: Nonexistent ID returns 404 (auth control exists) ✓
    Signal 4: Response structure matches known user data schema ✓
    → 3/4 signals = report with MEDIUM confidence (still needs manual verify)

For SSRF to be reported:
    Signal 1: Metadata signature found in response body ✓ (DIRECT — high confidence)
    OR:
    Signal 1: Response delayed consistently across 3 probes ✓
    Signal 2: Delay is proportionally larger than 3x baseline ✓
    Signal 3: Delay disappears when payload is not a real host ✓
    → 2/3 time-based signals = report with LOW confidence (needs OOB confirmation)
"""


# ═══════════════════════════════════════════════════════════════════════════
# PART 3: THE NEW ARCHITECTURE — LAYER BY LAYER
# ═══════════════════════════════════════════════════════════════════════════

"""
─────────────────────────────────────────────────────────────────────────────
NEW PIPELINE ARCHITECTURE
─────────────────────────────────────────────────────────────────────────────

OLD (Phase 1+2):
    URL → Param Extract → Inject → Check Response → Score → Report

NEW (Phase 3+):

    ┌─────────────────────────────────────────────────────────────┐
    │  TRANSPORT LAYER                                             │
    │  Session management, cookie handling, rate limiting,         │
    │  retry logic, proxy routing                                  │
    └──────────────────────────┬──────────────────────────────────┘
                               │ HTTPResponse objects
    ┌──────────────────────────▼──────────────────────────────────┐
    │  BASELINE CALIBRATION LAYER                                  │
    │  Learn what "normal" looks like BEFORE injecting anything.   │
    │  Multiple clean requests. Measure variance. Identify         │
    │  dynamic sections (timestamps, CSRF tokens, ads).            │
    └──────────────────────────┬──────────────────────────────────┘
                               │ BaselineProfile objects
    ┌──────────────────────────▼──────────────────────────────────┐
    │  MUTATION LAYER                                              │
    │  Generate test inputs. Context-aware mutation.               │
    │  Not random payloads — targeted mutations based on           │
    │  parameter type, value type, and application context.        │
    └──────────────────────────┬──────────────────────────────────┘
                               │ MutatedRequest objects
    ┌──────────────────────────▼──────────────────────────────────┐
    │  COLLECTION LAYER                                            │
    │  Execute requests. Collect full response objects.            │
    │  Measure timing accurately (3 samples minimum).              │
    │  Handle errors, redirects, rate limiting.                    │
    └──────────────────────────┬──────────────────────────────────┘
                               │ ResponseCollection objects
    ┌──────────────────────────▼──────────────────────────────────┐
    │  NORMALIZATION LAYER                                         │
    │  Strip dynamic content (timestamps, CSRF, session data).     │
    │  Normalize whitespace, HTML structure, encoding.             │
    │  Produce stable "fingerprints" for comparison.               │
    └──────────────────────────┬──────────────────────────────────┘
                               │ NormalizedResponse objects
    ┌──────────────────────────▼──────────────────────────────────┐
    │  RESPONSE INTELLIGENCE ENGINE                                │
    │  Semantic similarity analysis (not just size diff).          │
    │  Structural diff (DOM tree comparison).                      │
    │  Content classification (is this public or private data?).   │
    │  Behavioral pattern detection.                               │
    └──────────────────────────┬──────────────────────────────────┘
                               │ IntelligenceReport objects
    ┌──────────────────────────▼──────────────────────────────────┐
    │  VALIDATION LAYER                                            │
    │  Module-specific validation pipelines.                       │
    │  IDOR: auth-aware testing, nonexistent ID probing.           │
    │  SSRF: statistical timing analysis, OOB preparation.         │
    │  XSS: context verification, encoding analysis.               │
    │  Each validation stage adds or removes evidence signals.     │
    └──────────────────────────┬──────────────────────────────────┘
                               │ ValidationResult objects
    ┌──────────────────────────▼──────────────────────────────────┐
    │  CONFIDENCE SCORING ENGINE                                   │
    │  Aggregate evidence signals.                                 │
    │  Calculate confidence percentage (0.0 → 1.0).               │
    │  Apply module-specific weighting.                            │
    │  Map confidence to severity.                                 │
    └──────────────────────────┬──────────────────────────────────┘
                               │ ScoredFinding objects with confidence
    ┌──────────────────────────▼──────────────────────────────────┐
    │  REPORTING LAYER                                             │
    │  Filter by confidence threshold.                             │
    │  Group related findings.                                     │
    │  Generate evidence chains.                                   │
    │  Output: CLI, JSON, Markdown, SQLite.                        │
    └─────────────────────────────────────────────────────────────┘


─────────────────────────────────────────────────────────────────────────────
3.1  BASELINE CALIBRATION LAYER — HOW IT WORKS
─────────────────────────────────────────────────────────────────────────────

Purpose:
    Before injecting anything, learn what the application returns
    normally. Build a statistical model of "normal" so we can
    identify genuine anomalies versus expected variance.

Algorithm:

    1. Send N=3 identical requests to the baseline URL
       (same parameters, same values as found in the wild)

    2. For each response, extract:
       - Status code
       - Content-Length
       - Body length
       - Response time
       - Set of dynamic tokens (CSRF, session IDs, nonces)
       - Structural HTML fingerprint (DOM node counts)
       - Content type

    3. Calculate variance metrics:
       - length_variance = max(lengths) - min(lengths)
       - time_variance = stddev(response_times)
       - structural_stability = jaccard(dom_tree_1, dom_tree_2)

    4. Identify dynamic sections:
       - Any section that differs between requests is "dynamic"
       - Mark dynamic sections so they are EXCLUDED from diffs
       - Common dynamic sections: timestamps, CSRF tokens, nonces,
         ad content, session identifiers

    5. Build BaselineProfile:
       {
           "url": url,
           "stable_length": median_length,
           "length_tolerance": length_variance * 2,  # 2x variance as threshold
           "dynamic_patterns": [regex patterns of dynamic content],
           "dom_fingerprint": stable_dom_hash,
           "timing_median": median_response_time,
           "timing_stddev": stddev_response_time,
           "is_authenticated": bool,
           "auth_signals": [cookies, headers that indicate auth],
       }

    Result: We now know what "normal" means for this specific URL.
    Any deviation beyond the calibrated tolerance is meaningful.


─────────────────────────────────────────────────────────────────────────────
3.2  NORMALIZATION LAYER — HOW IT WORKS
─────────────────────────────────────────────────────────────────────────────

Purpose:
    Make responses comparable by removing content that changes
    between requests for reasons UNRELATED to vulnerabilities.

Normalization steps applied in order:

    STEP 1: Token Stripping
        Remove: CSRF tokens, nonces, session IDs from response body
        Pattern: anything matching the dynamic_patterns from baseline
        Why: These change every request. They would always show as "different".

    STEP 2: Timestamp Normalization
        Replace: all date/time strings with a placeholder
        Patterns: ISO 8601, Unix timestamps, relative times ("2 hours ago")
        Why: Server time changes between requests. Not vulnerability-related.

    STEP 3: Whitespace Normalization
        Collapse: multiple spaces/tabs/newlines to single space
        Why: Server-side template engines sometimes produce different
             whitespace. This is not meaningful for comparison.

    STEP 4: Numeric Value Abstraction (for IDOR specifically)
        Don't strip numbers entirely, but track WHICH numbers change.
        If a number in position X changes between id=1 and id=2,
        that number is likely the content data (expected to change).
        If a number in position Y stays the same, it might be a
        structural element.

    STEP 5: HTML Structure Normalization
        Parse HTML → extract DOM tree → normalize attribute ordering
        Why: Some frameworks render attributes in random order.
             Comparing raw HTML strings would show false differences.

    STEP 6: Encoding Normalization
        Convert HTML entities → decoded characters
        Convert URL encoding → decoded characters
        Why: %3Cscript%3E and &lt;script&gt; are the same thing.
             We should compare decoded content consistently.

    Result: NormalizedResponse object with:
        - stripped_body: body with dynamic content removed
        - dom_fingerprint: structural hash
        - content_tokens: set of meaningful content words
        - numeric_positions: map of where numbers appear and their values


─────────────────────────────────────────────────────────────────────────────
3.3  RESPONSE INTELLIGENCE ENGINE — SEMANTIC SIMILARITY
─────────────────────────────────────────────────────────────────────────────

Purpose:
    Instead of "size difference > threshold", compute a SIMILARITY SCORE
    between two normalized responses. This tells us HOW DIFFERENT the
    responses are and WHETHER that difference is meaningful.

Similarity Metrics (computed together, not individually):

    METRIC 1: Token-level Jaccard Similarity
        tokens_A = set of words in normalized response A
        tokens_B = set of words in normalized response B
        jaccard = |tokens_A ∩ tokens_B| / |tokens_A ∪ tokens_B|
        Range: 0.0 (completely different) → 1.0 (identical)

        For public blog posts: jaccard might be 0.3 (different content words)
        For same user's data with different ID: might be 0.1 (different name/email)
        For truly unauthorized access: might be 0.05 (completely different user)

    METRIC 2: Structural Similarity
        Compare DOM node counts, nesting levels, class names
        If structure is the same but content differs: same template, different data
        If structure is completely different: different page type

    METRIC 3: Length Ratio
        ratio = len(response_B) / len(response_A)
        If ratio is 1.0 ± tolerance: similar length
        If ratio is very different (0.1 or 10.0): significantly different content

    METRIC 4: Semantic Field Analysis (NEW - key differentiator)
        Classify content into semantic categories:
        - "user_data": names, emails, addresses, phone numbers
        - "public_content": article text, blog posts, product descriptions
        - "system_data": error messages, stack traces, config values
        - "auth_data": tokens, session IDs, passwords

        If semantic field changes from "public_content" to "user_data":
            This is more suspicious than just content changing.
        If semantic field stays "public_content" for different IDs:
            This is expected. Not suspicious. Don't report.

    COMPOSITE SCORE:
        similarity = (
            0.35 * jaccard_similarity +
            0.25 * structural_similarity +
            0.20 * (1.0 - length_ratio_deviation) +
            0.20 * semantic_consistency_score
        )

        For public content (blog posts): similarity ≈ 0.3–0.5 (expected to differ)
        For IDOR candidate: similarity ≈ 0.05–0.2 AND semantic field changed
        For exact same content: similarity ≈ 0.95–1.0


─────────────────────────────────────────────────────────────────────────────
3.4  CONFIDENCE SCORING ENGINE — REPLACING POINT SCORES
─────────────────────────────────────────────────────────────────────────────

Purpose:
    Replace the current additive point system with a probabilistic
    confidence model. Each evidence signal votes for or against a finding.
    The final output is a confidence percentage with evidence tracing.

Why confidence instead of points:
    Points are linear and additive. Confidence is multiplicative and Bayesian.
    Two independent signals that each have 70% confidence combine to 91%,
    not 140% (which is impossible and meaningless).

Confidence model:

    For each evidence signal, define:
        - base_confidence: probability this signal indicates vulnerability (0.0-1.0)
        - weight: how much this signal matters relative to others

    IDOR Confidence Signals:

        SIGNAL: Response returns HTTP 200 for modified ID
            base_confidence: 0.3  (weak — public content also returns 200)
            weight: 0.1

        SIGNAL: Content semantically different (similarity < 0.3)
            base_confidence: 0.4  (moderate — content changed, could be public)
            weight: 0.15

        SIGNAL: Semantic field changed to "user_data"
            base_confidence: 0.7  (strong — user data appeared)
            weight: 0.25

        SIGNAL: PII pattern matched (email, phone, SSN)
            base_confidence: 0.85  (very strong — specific private data found)
            weight: 0.3

        SIGNAL: Nonexistent ID returns 404 (auth control exists)
            base_confidence: 0.8  (strong — server enforces existence, just not ownership)
            weight: 0.2

        COMBINED CONFIDENCE = weighted average of active signals
        REPORT THRESHOLD: confidence >= 0.60 for MEDIUM, >= 0.80 for HIGH

    SSRF Confidence Signals:

        SIGNAL: Metadata signature in response body
            base_confidence: 0.95  (near-certain — metadata strings are unique)
            weight: 0.7

        SIGNAL: Statistical timing delay (>2x baseline across 3 probes)
            base_confidence: 0.5  (moderate — could be network)
            weight: 0.2

        SIGNAL: Different timing with invalid IP (no delay)
            base_confidence: 0.65  (good — confirms timing is IP-specific)
            weight: 0.1

        SIGNAL: OOB callback received (Phase 3 - Collaborator)
            base_confidence: 0.99  (essentially certain)
            weight: 1.0  (overrides everything — auto HIGH)


─────────────────────────────────────────────────────────────────────────────
3.5  AUTH-AWARE TESTING — THE KEY TO REAL IDOR DETECTION
─────────────────────────────────────────────────────────────────────────────

Purpose:
    Test access control by understanding the authentication state
    of the current session and using it deliberately.

Current scanner problem: it doesn't know if it's authenticated.
It injects payloads with whatever cookies/headers are configured,
but doesn't reason about what those credentials mean.

Auth-Aware Testing Pipeline:

    STEP 1: Auth Detection
        Before testing any parameter, detect authentication signals:
        - Presence of session cookies (PHPSESSID, sessionid, .ASPXAUTH, jwt, etc.)
        - Authorization headers (Bearer, Basic)
        - User-identifying response content (username, email in DOM)

        If no auth signals detected:
            Mark as UNAUTHENTICATED_CONTEXT
            IDOR testing without auth = meaningless on protected endpoints
            Still test but confidence is automatically reduced by 50%

    STEP 2: Identity Extraction
        If authenticated, try to extract "my" identity from the application:
        - Look for user ID in DOM: data-user-id, current_user, profile URL
        - Look for user ID in cookies: user_id=, uid=
        - Look for user ID in URLs: /user/1234/settings

        This gives us OUR_ID. Now we know what's "ours" vs "theirs".

    STEP 3: Ownership-Aware Parameter Testing
        If param.value == OUR_ID:
            → This is OUR resource. Changing it tests cross-user access.
            → This is the CORRECT IDOR test.
            → Run full validation pipeline.
        If param.value != OUR_ID and param.value is numeric:
            → We're already accessing someone else's ID.
            → Either it's public or there's already an IDOR.
            → Test whether it should be public: probe nonexistent ID.

    STEP 4: Nonexistent ID Oracle
        For any numeric parameter, probe an ID that almost certainly doesn't exist:
        - Try id=0, id=-1, id=999999999
        - If these return 404: the endpoint enforces ID validity
        - If these return 200 with some content: the endpoint doesn't validate IDs
          → Any ID change result is now more suspicious

    STEP 5: Cross-Account Validation (when two sessions available)
        If the user provides a second set of cookies (--session2 flag in Phase 3):
        - Make request with session_A cookies → note the ID
        - Make same request with session_B cookies → note session_B's ID
        - Use session_A to request session_B's ID
        - If session_B's data is returned: CONFIRMED IDOR (highest confidence)

─────────────────────────────────────────────────────────────────────────────
3.6  SQLI VALIDATION ARCHITECTURE
─────────────────────────────────────────────────────────────────────────────

Current state: We have no SQLi module yet. Here's how to build it correctly.

SQLi validation requires THREE independent probing techniques to agree:

    TECHNIQUE 1: Error-Based Detection
        Inject syntax errors and look for database error strings.
        Not just "response changed" — look for SPECIFIC error patterns:

        MySQL errors:    "You have an error in your SQL syntax"
                         "mysql_fetch_array()"
                         "Warning: mysql_"
        PostgreSQL:      "pg_query()"
                         "ERROR: unterminated quoted string"
        MSSQL:           "Microsoft SQL Native Client error"
                         "Unclosed quotation mark"
        Oracle:          "ORA-01756"
                         "quoted string not properly terminated"

        Confidence: 0.85 if specific error string matched

    TECHNIQUE 2: Boolean-Based Blind Detection
        Inject conditions that should be TRUE or FALSE and
        compare responses. The comparison is STRUCTURAL, not just size.

        TRUE condition:  id=1 AND 1=1    → should return same as id=1
        FALSE condition: id=1 AND 1=2    → should return different (empty/error)

        Validation:
        - response(id=1) ≈ response(id=1 AND 1=1): similarity > 0.95
        - response(id=1) ≠ response(id=1 AND 1=2): similarity < 0.3
        - BOTH must hold to report

        Confidence: 0.75 if both conditions hold consistently
        MUST repeat 3 times with different payloads to confirm

    TECHNIQUE 3: Time-Based Blind Detection
        Inject time delay payloads and measure execution time.
        Same statistical approach as SSRF timing:

        MySQL:      id=1 AND SLEEP(3)
        PostgreSQL: id=1; SELECT pg_sleep(3)
        MSSQL:      id=1; WAITFOR DELAY '0:0:3'

        Requires:
        - 3 baseline measurements
        - 3 probe measurements
        - median(probes) - median(baselines) > delay_value * 0.8
        - Standard deviation of probes must be small (consistent delay)

        Confidence: 0.65 if timing is consistent across 3 probes
                    Requires human/OOB confirmation before reporting HIGH

    COMBINED SQLi CONFIDENCE:
        If any technique reaches 0.85+: report immediately
        If two techniques reach 0.60+: report with combined confidence
        If only one technique below 0.60: flag for manual review, don't report


─────────────────────────────────────────────────────────────────────────────
3.7  CSRF ARCHITECTURE
─────────────────────────────────────────────────────────────────────────────

CSRF is different from all other modules — it's not about injecting payloads.
It's about testing whether state-changing requests REQUIRE proof of user intent.

CSRF Validation Pipeline:

    STEP 1: State-Changing Endpoint Identification
        Look for POST/PUT/DELETE requests that:
        - Change user data (email, password, settings)
        - Perform financial operations (transfer, purchase)
        - Administrative actions (delete, promote)

        These are CSRF candidates. GET requests that change state
        are also candidates (and worse — can be embedded in images).

    STEP 2: CSRF Token Detection
        For each state-changing endpoint, check:
        - Is there a CSRF token in the request? (body, header, cookie)
        - If yes: does removing it cause a 403/error?
        - If no token: potential CSRF

    STEP 3: Token Validation Testing
        If a token exists:
        - Test with wrong token: does the server reject it?
        - Test with token from a different session: does the server reject it?
        - Test with no token: does the server reject it?

        If the server accepts any of these: CSRF confirmed

    STEP 4: SameSite Cookie Analysis
        Check Set-Cookie headers for SameSite attribute:
        - SameSite=Strict: CSRF protected (modern browsers)
        - SameSite=Lax: Partially protected
        - SameSite=None or missing: Not protected by cookie policy

    STEP 5: Origin/Referer Validation Testing
        Some apps check Origin/Referer headers instead of tokens:
        - Omit Origin header: does server accept?
        - Send wrong Origin: does server accept?
        - If yes to either: CSRF via origin bypass

    Confidence:
        No token + SameSite=None: 0.90 (high confidence CSRF)
        Wrong token accepted: 0.95 (near-certain CSRF)
        No token + SameSite=Lax: 0.50 (conditional on browser version)


─────────────────────────────────────────────────────────────────────────────
3.8  HOW MODULES SHOULD AGGREGATE EVIDENCE
─────────────────────────────────────────────────────────────────────────────

Each module should produce an EvidenceBundle, not a boolean finding.

EvidenceBundle structure:
    {
        "module": "IDOR",
        "url": url,
        "parameter": param_name,
        "signals": [
            {
                "name": "status_200_for_adjacent_id",
                "observed": True,
                "confidence_contribution": 0.3,
                "evidence": "HTTP 200 received for id=2 (baseline id=1)",
            },
            {
                "name": "semantic_field_changed",
                "observed": True,
                "confidence_contribution": 0.7,
                "evidence": "Response semantic field: public_content → user_data",
            },
            {
                "name": "pii_detected",
                "observed": True,
                "confidence_contribution": 0.85,
                "evidence": "Email pattern found: j***@example.com",
            },
            {
                "name": "nonexistent_id_returns_404",
                "observed": True,
                "confidence_contribution": 0.8,
                "evidence": "id=999999 → HTTP 404",
            },
        ],
        "combined_confidence": 0.73,
        "severity": "MEDIUM",
        "requires_manual_verification": True,
        "false_positive_risk": "LOW",
    }

The reporting layer then filters:
    confidence >= 0.80: AUTO_REPORT (HIGH severity findings)
    confidence >= 0.60: REPORT_WITH_NOTE (MEDIUM — verify manually)
    confidence >= 0.40: FLAG_FOR_REVIEW (LOW — interesting, not reportable)
    confidence < 0.40:  SUPPRESS (false positive risk too high)
"""


# ═══════════════════════════════════════════════════════════════════════════
# PART 4: PHASE 3 IMPLEMENTATION ROADMAP
# ═══════════════════════════════════════════════════════════════════════════

"""
─────────────────────────────────────────────────────────────────────────────
PHASE 3 MODULE BUILD ORDER
─────────────────────────────────────────────────────────────────────────────

Build in this exact order. Each layer depends on the previous.

SPRINT 1: Foundation (build these first, everything else depends on them)
─────────────────────────────────────────────────────────────────────────────

  File 1: core/intelligence/baseline_calibrator.py
    - Send N=3 clean requests per URL
    - Measure length variance, timing variance
    - Identify dynamic sections (regex-based)
    - Build BaselineProfile dataclass
    - Output: BaselineProfile

  File 2: core/intelligence/normalizer.py
    - Strip dynamic tokens (CSRF, timestamps, nonces)
    - Normalize whitespace and encoding
    - Build NormalizedResponse dataclass
    - Output: NormalizedResponse

  File 3: core/intelligence/similarity_engine.py
    - Jaccard token similarity
    - Structural DOM similarity (BeautifulSoup)
    - Length ratio analysis
    - Composite similarity score
    - Output: SimilarityReport (float 0.0–1.0 + breakdown)

  File 4: core/intelligence/semantic_classifier.py
    - Classify response content into semantic fields
    - user_data, public_content, system_data, auth_data, error_data
    - PII pattern detection (regex + context)
    - Output: SemanticProfile

  File 5: core/intelligence/confidence_engine.py
    - EvidenceBundle dataclass
    - Signal registration and weighting
    - Confidence calculation (weighted average)
    - Severity mapping from confidence
    - Output: ScoredEvidenceBundle


SPRINT 2: Auth Layer
─────────────────────────────────────────────────────────────────────────────

  File 6: core/auth/auth_detector.py
    - Detect session cookies in requests/responses
    - Detect Authorization headers
    - Detect user-identifying content in DOM
    - Output: AuthContext dataclass

  File 7: core/auth/identity_extractor.py
    - Extract OUR_ID from authenticated session
    - Extract user identifiers from DOM
    - Build IdentityProfile


SPRINT 3: Module Redesign
─────────────────────────────────────────────────────────────────────────────

  File 8: modules/idor/idor_validator.py (REPLACES idor_tester.py)
    - Auth-aware parameter classification
    - Nonexistent ID oracle
    - Semantic similarity comparison (not size diff)
    - EvidenceBundle output

  File 9: modules/ssrf/ssrf_validator.py (REPLACES ssrf_tester.py)
    - Statistical timing (3 samples)
    - Direct signature detection (unchanged, already good)
    - OOB preparation (Collaborator URL insertion)
    - EvidenceBundle output

  File 10: modules/sqli/ (NEW)
    - Error-based detection
    - Boolean-based blind detection
    - Time-based blind detection
    - Database fingerprinting
    - EvidenceBundle output

  File 11: modules/csrf/ (NEW)
    - State-changing endpoint detection
    - Token validation testing
    - SameSite analysis
    - Origin bypass testing
    - EvidenceBundle output


SPRINT 4: New Features
─────────────────────────────────────────────────────────────────────────────

  File 12: core/utils/async_client.py
    - asyncio + aiohttp replacement for requests
    - Concurrent request processing
    - Rate limiting per domain
    - 10x speed improvement

  File 13: modules/jwt/ (NEW)
    - JWT detection in responses and cookies
    - Algorithm confusion testing (RS256→HS256)
    - None algorithm testing
    - Weak secret detection
    - kid/jku injection

  File 14: modules/graphql/ (NEW)
    - GraphQL endpoint discovery
    - Introspection query
    - Field injection testing
    - Batch query abuse

  File 15: ui/web_dashboard/ (NEW)
    - Flask backend serving finding data
    - React frontend with severity charts
    - Finding timeline view
    - Session comparison


─────────────────────────────────────────────────────────────────────────────
THE KEY PRINCIPLE FOR ALL NEW CODE
─────────────────────────────────────────────────────────────────────────────

BEFORE THIS REDESIGN:
    "Response changed → vulnerability"

AFTER THIS REDESIGN:
    "Response changed AND semantic content changed AND auth boundary exists
     AND change is consistent across multiple probes AND confidence ≥ 0.60
     → PROBABLE vulnerability (requires manual verification)"

    "Response contains metadata signatures AND signatures are unambiguous
     AND probe was targeted (not accidental) → CONFIRMED vulnerability"

The difference:
    OLD: One signal → report
    NEW: Multiple independent signals → calculate confidence → report with evidence chain

This is how Burp Suite Pro works.
This is how commercial scanners work.
This is the standard you're building toward.
"""
