// ─────────────────────────────────────────────────────────────────────────────
// ollama-explanation.service.js — generează explicația în limbaj natural a
// verdictului ("de ce e suspicious / safe / likely_phishing").
//
// Ce face, pe scurt: primește verdictul deja calculat, scorurile (final/reguli/AI),
// regulile declanșate și semnalele AI, și cere modelului AI local (Ollama) să scrie
// 1-3 propoziții simple, pe înțelesul unui utilizator non-tehnic, care explică
// userului DE CE emailul a primit acel verdict, plus o recomandare practică
// (ex. "nu deschide linkurile").
//
// Important: modelul NU decide verdictul sau scorul — acestea sunt deja fixe,
// calculate în scan.service.js. AI-ul are voie doar să "povestească" rezultatul.
// Dacă AI e oprit sau eșuează (timeout, output invalid), funcția întoarce un
// rezultat 'failed', iar scan.service.js (resolveExplanationResult) cade pe un
// fallback controlat din scan-explanation.service.js — userul vede mereu o
// explicație, generată de AI sau dintr-un șablon fix.
//
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_MS,
} from '../config/env.js';

const DEFAULT_OLLAMA_BASE_URL = 'http://127.0.0.1:11434';
const DEFAULT_OLLAMA_MODEL = OLLAMA_MODEL || 'qwen2.5:7b-instruct'
const DEFAULT_OLLAMA_TIMEOUT_MS = 45000;
const MAX_EXPLANATION_TIMEOUT_MS = 600000;
const PROMPT_VERSION = 'explanation-v3';

// "Explicație goală" — folosită ca rezultat când AI eșuează. scan.service.js
// detectează acest caz (status !== 'generated') și pune fallback-ul controlat.
const EMPTY_EXPLANATION = {
    summary: '',
};

// Modelele AI răspund uneori cu JSON înfășurat în ```json ... ``` (markdown code
// fence). Funcția asta scoate aceste delimitatoare, ca să rămână JSON curat de parsat.
const stripCodeFence = (value) =>
    value
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

// Normalizează adresa de bază a serverului Ollama (ex. adaugă "http://" dacă lipsește,
// scoate "/" de la final).
const normalizeBaseUrl = (rawValue) => {
    const trimmedValue = String(rawValue || '').trim();

    if (!trimmedValue) {
        return DEFAULT_OLLAMA_BASE_URL;
    }

    if (trimmedValue.startsWith('http://') || trimmedValue.startsWith('https://')) {
        return trimmedValue.replace(/\/+$/, '');
    }

    return `http://${trimmedValue.replace(/\/+$/, '')}`;
};

// Construiește o listă de adrese "candidat" pentru serverul Ollama: adresa
// configurată, plus variante echivalente localhost <-> 127.0.0.1, plus adresa
// implicită ca ultimă variantă de rezervă. Se încearcă în ordine, până la prima
// care răspunde.
const buildCandidateBaseUrls = () => {
    const normalizedConfiguredBaseUrl = normalizeBaseUrl(
        OLLAMA_BASE_URL || DEFAULT_OLLAMA_BASE_URL
    );
    const candidateUrls = [normalizedConfiguredBaseUrl];

    try {
        const parsedConfiguredUrl = new URL(normalizedConfiguredBaseUrl);

        if (parsedConfiguredUrl.hostname === 'localhost') {
            candidateUrls.push(
                normalizedConfiguredBaseUrl.replace('://localhost', '://127.0.0.1')
            );
        }

        if (parsedConfiguredUrl.hostname === '127.0.0.1') {
            candidateUrls.push(
                normalizedConfiguredBaseUrl.replace('://127.0.0.1', '://localhost')
            );
        }
    } catch {
        candidateUrls.push(DEFAULT_OLLAMA_BASE_URL);
    }

    if (!candidateUrls.includes(DEFAULT_OLLAMA_BASE_URL)) {
        candidateUrls.push(DEFAULT_OLLAMA_BASE_URL);
    }

    return [...new Set(candidateUrls)];
};

// Metadatele de bază atașate la orice rezultat (succes sau eroare): de unde vine
// (ollama), ce model și ce versiune de prompt s-a folosit.
const buildBaseMeta = () => ({
    source: 'ollama',
    model: OLLAMA_MODEL || DEFAULT_OLLAMA_MODEL,
    promptVersion: PROMPT_VERSION,
});

// Timeout configurabil din env (OLLAMA_TIMEOUT_MS), plafonat între 5 secunde și
// 10 minute (MAX_EXPLANATION_TIMEOUT_MS) — explicațiile pot dura mai mult pe
// scanări în fundal cu modele mai lente.
const clampTimeoutMs = () => {
    const parsedTimeoutMs = Number.parseInt(
        String(OLLAMA_TIMEOUT_MS || DEFAULT_OLLAMA_TIMEOUT_MS),
        10
    );

    if (!Number.isFinite(parsedTimeoutMs)) {
        return DEFAULT_OLLAMA_TIMEOUT_MS;
    }

    return Math.min(Math.max(parsedTimeoutMs, 5000), MAX_EXPLANATION_TIMEOUT_MS);
};

// Asigură că scorul e un număr valid între 0 și 100 (apără promptul de valori
// ciudate, ex. NaN sau negative, care ar deruta modelul AI).
const normalizeScore = (value) => {
    const score = Number(value);

    if (!Number.isFinite(score)) {
        return 0;
    }

    return Math.min(Math.max(score, 0), 100);
};

// Construiește obiectul de input trimis modelului AI: verdictul și scorurile deja
// calculate (NU se cer din nou de la AI — modelul doar le "explică"), plus
// regulile declanșate și semnalele AI care au dus la acel verdict.
const buildExplanationInput = ({
    verdict,
    score,
    ruleScore,
    aiScore,
    triggeredRules,
    aiSignals,
}) => ({
    verdict: String(verdict || '').trim(),
    score: normalizeScore(score),
    ruleScore: normalizeScore(ruleScore),
    aiScore: normalizeScore(aiScore),
    triggeredRules: Array.isArray(triggeredRules) ? triggeredRules : [],
    aiSignals: aiSignals && typeof aiSignals === 'object' ? aiSignals : {},
});

// Promptul de SISTEM: instrucțiunile date modelului AI. Cere explicit modelului
// să NU schimbe verdictul/scorurile și să NU inventeze motive — doar să rezume
// în 1-3 propoziții simple, pentru un utilizator non-tehnic, plus o recomandare
// practică (diferită pentru "safe" față de "suspicious"/"likely_phishing").
const buildExplanationSystemPrompt = () => `
You are a cybersecurity analyst who writes a very short phishing-scan explanation for
non-technical users.

Return ONLY valid JSON. No markdown. No text before or after JSON.
Write the summary in English.

Rules:
- Do not change the provided verdict.
- Do not change the provided scores.
- Do not invent reasons.
- Use only triggeredRules and aiSignals.
- Write 1 to 3 short sentences.
- First mention the main risk level or signal.
- End with a small practical recommendation.
- If the verdict is safe, recommend normal caution, not alarm.
- If the verdict is suspicious or likely_phishing, recommend not opening links or verifying the sender.

Required JSON:
{
  "summary": "string"
}
`.trim();

// Promptul de USER: datele scanării (din buildExplanationInput), trimise modelului
// ca JSON, cu instrucțiunea de a genera doar rezumatul cerut.
const buildExplanationUserPrompt = (explanationInput) => `
Create only the JSON summary from this scan data:
${JSON.stringify(explanationInput)}
`.trim();

// Taie un text la maximum `maxLength` caractere, după ce elimină spațiile de la margini.
const normalizeText = (value, maxLength) => String(value || '').trim().slice(0, maxLength);

// Validează răspunsul brut al modelului AI: trebuie să fie JSON valid, un obiect
// (nu listă), și să conțină un câmp "summary" nevid. Întoarce fie
// { isValid: true, explanation } fie { isValid: false, reason } — folosit mai jos
// ca să decidem dacă generarea a avut succes ('generated') sau a eșuat ('failed').
const validateExplanationOutput = (rawValue) => {
    const invalid = (reason) => ({ isValid: false, reason });
    const cleanedValue = stripCodeFence(String(rawValue || ''));
    // Extragem doar porțiunea dintre prima '{' și ultima '}' — unele modele mai
    // adaugă text înainte/după JSON, chiar dacă li s-a cerut "doar JSON".
    const firstObjectIndex = cleanedValue.indexOf('{');
    const lastObjectIndex = cleanedValue.lastIndexOf('}');
    const jsonCandidate =
        firstObjectIndex >= 0 && lastObjectIndex > firstObjectIndex
            ? cleanedValue.slice(firstObjectIndex, lastObjectIndex + 1)
            : cleanedValue;
    let parsedValue;

    try {
        parsedValue = JSON.parse(jsonCandidate);
    } catch {
        return invalid('invalid_json');
    }

    if (!parsedValue || typeof parsedValue !== 'object' || Array.isArray(parsedValue)) {
        return invalid('invalid_shape');
    }

    const explanation = {
        summary: normalizeText(parsedValue.summary, 320),
    };

    if (!explanation.summary) {
        return invalid('missing_summary');
    }

    return {
        isValid: true,
        explanation,
    };
};

// Construiește rezultatul pentru cazul de eșec (status 'failed'): explicație goală
// + metadate cu motivul eșecului. scan.service.js va detecta status !== 'generated'
// și va folosi fallback-ul controlat (din scan-explanation.service.js) în loc.
const buildFailedResult = ({ baseMeta, latencyMs, fallbackUsed, fallbackReason }) => {
    console.error('[ollama-explanation] Explanation generation failed', {
        fallbackReason,
        latencyMs,
        hostFallbackUsed: fallbackUsed,
    });

    return {
        explanation: EMPTY_EXPLANATION,
        meta: {
            status: 'failed',
            ...baseMeta,
            latencyMs,
            hostFallbackUsed: fallbackUsed,
            hostFallbackReason: fallbackUsed ? 'local_host_fallback' : null,
            fallbackReason,
            evaluatedAt: new Date(),
        },
    };
};

// Funcția principală a fișierului: cere modelului AI local să scrie explicația
// "de ce" pentru un verdict deja calculat. Apelată din scan.service.js doar dacă
// userul are AI pornit (vezi shouldGenerateNaturalExplanation).
//
// Parametri: verdictul, scorurile (final/reguli/AI), regulile declanșate și
// semnalele AI — toate deja calculate, AI-ul doar le explică în cuvinte.
export const generateNaturalExplanationWithOllama = async ({
    verdict,
    score,
    ruleScore,
    aiScore,
    triggeredRules,
    aiSignals,
}) => {
    const baseMeta = buildBaseMeta();
    const ollamaTimeoutMs = clampTimeoutMs();
    const candidateBaseUrls = buildCandidateBaseUrls();
    const explanationInput = buildExplanationInput({
        verdict,
        score,
        ruleScore,
        aiScore,
        triggeredRules,
        aiSignals,
    });
    // Corpul cererii HTTP trimisă la Ollama: modelul, promptul de sistem + cel de
    // user, și opțiuni precum temperature: 0 (răspunsuri deterministe).
    const requestBody = JSON.stringify({
        model: baseMeta.model,
        stream: false,
        format: 'json',
        options: {
            temperature: 0,
            num_predict: 80,
        },
        messages: [
            {
                role: 'system',
                content: buildExplanationSystemPrompt(),
            },
            {
                role: 'user',
                content: buildExplanationUserPrompt(explanationInput),
            },
        ],
    });

    let lastNetworkError = null;

    // Încercăm pe rând fiecare adresă candidat a serverului Ollama, până la prima
    // care răspunde cu succes. `candidateIndex > 0` înseamnă că am folosit o
    // adresă de rezervă (fallback) în loc de cea configurată implicit.
    for (const [candidateIndex, candidateBaseUrl] of candidateBaseUrls.entries()) {
        const startedAt = Date.now();
        const controller = new AbortController();
        // AbortController = mecanismul JS de a anula o cerere fetch în desfășurare,
        // dacă serverul Ollama nu răspunde în `ollamaTimeoutMs`.
        const timeoutId = setTimeout(() => controller.abort(), ollamaTimeoutMs);
        const fallbackUsed = candidateIndex > 0;
        const fallbackReason = fallbackUsed ? 'local_host_fallback' : null;

        try {
            const response = await fetch(`${candidateBaseUrl}/api/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                signal: controller.signal,
                body: requestBody,
            });

            const payload = await response.json().catch(() => ({}));
            const latencyMs = Date.now() - startedAt;

            // Eroare HTTP de la Ollama (server pornit, dar a răspuns cu eroare).
            if (!response.ok) {
                return buildFailedResult({
                    baseMeta,
                    latencyMs,
                    fallbackUsed,
                    fallbackReason: payload.error || `ollama_http_${response.status}`,
                });
            }

            const validatedOutput = validateExplanationOutput(payload?.message?.content);

            // Output invalid (nu e JSON, sau lipsește "summary") -> tratăm ca eșec,
            // scan.service.js va folosi fallback-ul controlat.
            if (!validatedOutput.isValid) {
                return buildFailedResult({
                    baseMeta,
                    latencyMs,
                    fallbackUsed,
                    fallbackReason: `ollama_invalid_output:${validatedOutput.reason}`,
                });
            }

            // Succes: AI a generat o explicație validă -> status 'generated'.
            return {
                explanation: validatedOutput.explanation,
                meta: {
                    status: 'generated',
                    ...baseMeta,
                    latencyMs,
                    hostFallbackUsed: fallbackUsed,
                    hostFallbackReason: fallbackReason,
                    evaluatedAt: new Date(),
                },
            };
        } catch (error) {
            const latencyMs = Date.now() - startedAt;

            // Cererea a fost anulată din cauza timeout-ului.
            if (error.name === 'AbortError') {
                return buildFailedResult({
                    baseMeta,
                    latencyMs,
                    fallbackUsed,
                    fallbackReason: 'ollama_timeout',
                });
            }

            // Eroare de rețea: păstrăm detaliile și încercăm și următoarea adresă
            // candidat din `candidateBaseUrls`.
            lastNetworkError = {
                latencyMs,
                fallbackUsed,
                fallbackReason: 'ollama_unreachable',
            };
        } finally {
            // Indiferent de rezultat, anulăm timer-ul de timeout ca să nu rămână activ.
            clearTimeout(timeoutId);
        }
    }

    // Toate adresele candidat au eșuat -> rezultat 'failed' cu ultima eroare de rețea
    // (sau valori implicite, dacă lista a fost goală).
    return buildFailedResult({
        baseMeta,
        latencyMs: lastNetworkError?.latencyMs || 0,
        fallbackUsed: lastNetworkError?.fallbackUsed || false,
        fallbackReason: lastNetworkError?.fallbackReason || 'ollama_unreachable',
    });
};
