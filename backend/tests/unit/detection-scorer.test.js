// ─────────────────────────────────────────────────────────────────────────────
// detection-scorer.test.js — ordinea și invariantele scorării centralizate.
//
// Nicio greutate nu vine din provider; scorerul aplică reduceri, plafoane și
// praguri într-un singur loc. Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import assert from 'node:assert/strict';
import test from 'node:test';

import { scoreSignals } from '../../src/detection/scorer.js';
import { mergeWeightModules } from '../../src/detection/weights/index.js';
import { AI_UNCORROBORATED_SCORE_MAX, RISK_THRESHOLDS } from '../../src/config/scoring.config.js';

const signal = ({
    key,
    kind = 'rule',
    order,
    sequence,
    rule = key,
    reason = key,
    details = key,
}) => ({
    key,
    kind,
    order,
    sequence,
    rule,
    reason,
    details,
});

test('scorer preserves legacy evidence order independent of provider emission order', () => {
    const result = scoreSignals([
        signal({
            key: 'urgency_high',
            kind: 'ai',
            order: 70,
            sequence: 0,
            rule: 'ai_semantic:urgency_high',
        }),
        signal({
            key: 'too_many_links_high',
            order: 60,
            sequence: 1,
        }),
        signal({
            key: 'high_risk_attachment_extension',
            order: 50,
            sequence: 2,
        }),
        signal({
            key: 'punycode_domain',
            order: 40,
            sequence: 4,
            rule: 'suspicious_link_pattern:punycode_domain',
        }),
        signal({
            key: 'ip_address_link',
            order: 40,
            sequence: 3,
            rule: 'suspicious_link_pattern:ip_address_link',
        }),
        signal({
            key: 'shortened_url_detected',
            order: 30,
            sequence: 5,
        }),
        signal({
            key: 'reply_to_mismatch',
            order: 20,
            sequence: 6,
        }),
        signal({
            key: 'user_blocklist_match',
            order: 10,
            sequence: 7,
        }),
    ]);

    assert.deepEqual(
        result.triggeredRules.map(({ rule }) => rule),
        [
            'user_blocklist_match',
            'reply_to_mismatch',
            'shortened_url_detected',
            'suspicious_link_pattern:ip_address_link',
            'suspicious_link_pattern:punycode_domain',
            'high_risk_attachment_extension',
            'too_many_links_high',
            'ai_semantic:urgency_high',
        ]
    );
});

test('scorer applies minimum context modifiers and omits zero-point evidence', () => {
    const result = scoreSignals(
        [
            signal({ key: 'reply_to_mismatch' }),
            signal({
                key: 'urgency_high',
                kind: 'ai',
                rule: 'ai_semantic:urgency_high',
            }),
            signal({
                key: 'social_engineering_high',
                kind: 'ai',
                rule: 'ai_semantic:social_engineering_high',
            }),
            signal({
                key: 'sensitive_data_request',
                kind: 'ai',
                rule: 'ai_semantic:sensitive_data_request',
            }),
        ],
        {
            senderVerifiedBrand: true,
            senderAllowlisted: true,
        }
    );

    assert.equal(result.ruleScore, 0);
    // Modifiers leave 26 AI points, but no rule signal fired, so the
    // uncorroborated cap clips the total to 25. See the dedicated test below.
    assert.equal(result.aiScore, 25);
    assert.deepEqual(
        result.triggeredRules.map(({ rule, points }) => ({ rule, points })),
        [
            { rule: 'ai_semantic:social_engineering_high', points: 6 },
            { rule: 'ai_semantic:sensitive_data_request', points: 20 },
        ]
    );
});

test('scorer normalizes structured provider details to the persisted string contract', () => {
    const result = scoreSignals([
        signal({
            key: 'reply_to_mismatch',
            details: { sender: 'example.com', replyTo: 'other.example' },
        }),
    ]);

    assert.equal(
        result.triggeredRules[0].details,
        '{"sender":"example.com","replyTo":"other.example"}'
    );
});

test('suspicious-link rules retain the legacy prefixed modifier lookup quirk', () => {
    const result = scoreSignals(
        [
            signal({
                key: 'very_long_url',
                rule: 'suspicious_link_pattern:very_long_url',
            }),
        ],
        {
            senderAllowlisted: true,
        }
    );

    assert.equal(result.ruleScore, 8);
});

test('blocklist points bypass all modifiers and force likely phishing', () => {
    const result = scoreSignals(
        [signal({ key: 'user_blocklist_match' })],
        {
            senderVerifiedBrand: true,
            senderAllowlisted: true,
        }
    );

    assert.equal(result.ruleScore, 60);
    assert.equal(result.verdict, 'likely_phishing');
});

test('AI contribution and final score are capped independently', () => {
    const result = scoreSignals([
        signal({ key: 'user_blocklist_match' }),
        signal({ key: 'high_risk_attachment_extension' }),
        signal({ key: 'reply_to_mismatch' }),
        signal({
            key: 'urgency_high',
            kind: 'ai',
            rule: 'ai_semantic:urgency_high',
        }),
        signal({
            key: 'sensitive_data_request',
            kind: 'ai',
            rule: 'ai_semantic:sensitive_data_request',
        }),
        signal({
            key: 'login_or_action_request',
            kind: 'ai',
            rule: 'ai_semantic:login_or_action_request',
        }),
        signal({
            key: 'social_engineering_high',
            kind: 'ai',
            rule: 'ai_semantic:social_engineering_high',
        }),
        signal({
            key: 'brand_impersonation_suspected',
            kind: 'ai',
            rule: 'ai_semantic:brand_impersonation_suspected',
        }),
    ]);

    assert.equal(result.ruleScore, 113);
    assert.equal(result.aiScore, 50);
    assert.equal(result.score, 100);
});

test('AI alone cannot leave the safe band without rule corroboration', () => {
    // Invariant 4. The local model is a small quantised one; measured against
    // qwen2.5:1.5b it asserted social engineering on every benign fixture in
    // tests/fixtures/semantic-eval.fixtures.js. Its unsupported opinion may
    // corroborate deterministic evidence and raise a borderline case, but it
    // must not author a verdict on its own.
    const aiOnly = [
        signal({ key: 'urgency_high', kind: 'ai', rule: 'ai_semantic:urgency_high' }),
        signal({ key: 'sensitive_data_request', kind: 'ai', rule: 'ai_semantic:sensitive_data_request' }),
        signal({ key: 'social_engineering_high', kind: 'ai', rule: 'ai_semantic:social_engineering_high' }),
        signal({ key: 'brand_impersonation_suspected', kind: 'ai', rule: 'ai_semantic:brand_impersonation_suspected' }),
    ];

    const uncorroborated = scoreSignals(aiOnly);

    assert.equal(uncorroborated.ruleScore, 0);
    assert.equal(uncorroborated.aiScore, AI_UNCORROBORATED_SCORE_MAX);
    assert.ok(
        uncorroborated.score < RISK_THRESHOLDS.suspicious,
        `AI-only score ${uncorroborated.score} must stay below ${RISK_THRESHOLDS.suspicious}`
    );
    assert.equal(uncorroborated.verdict, 'safe');
    // The evidence still reaches the UI — it is the score that is withheld.
    assert.equal(uncorroborated.triggeredRules.length, 4);

    // One deterministic signal is enough to lift the cap back to AI_SCORE_MAX.
    const corroborated = scoreSignals([...aiOnly, signal({ key: 'reply_to_mismatch' })]);

    assert.equal(corroborated.aiScore, 50);
    assert.equal(corroborated.verdict, 'likely_phishing');
});

test('unknown signal weights fail loudly', () => {
    assert.throws(
        () => scoreSignals([signal({ key: 'not_registered' })]),
        /Unknown detection signal weight: not_registered/
    );
});

test('weight merging rejects duplicate keys instead of overwriting', () => {
    assert.throws(
        () =>
            mergeWeightModules([
                { shared_signal: 10 },
                { other_signal: 20, shared_signal: 30 },
            ]),
        /Duplicate detection weight key: shared_signal/
    );
    assert.deepEqual(
        mergeWeightModules([{ first: 1 }, { second: 2 }]),
        { first: 1, second: 2 }
    );
});

test('reserved blocklist key cannot be shadowed by a weight module', () => {
    assert.throws(
        () => mergeWeightModules([{ user_blocklist_match: 1 }]),
        /Reserved detection weight key: user_blocklist_match/
    );
});

test('a module-level duplicate collision rejects during import', async () => {
    await assert.rejects(
        import(
            new URL(
                '../fixtures/duplicate-weight-module.js',
                import.meta.url
            )
        ),
        /Duplicate detection weight key: import_time_collision/
    );
});
