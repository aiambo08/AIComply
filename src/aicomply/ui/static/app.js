'use strict';

let currentScanData = null;
let selectedFindingIndex = 0;
let uploadedBundle = null;
let dossierMarkdown = null;
let busy = false;
const MAX_EVIDENCE_BYTES = 1024 * 1024;

function element(id) {
    return document.getElementById(id);
}

function text(id, value) {
    element(id).textContent = value ?? '--';
}

function node(tag, content, className = '') {
    const result = document.createElement(tag);
    result.textContent = content ?? '';
    result.className = className;
    return result;
}

async function request(path, payload) {
    const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(35000),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
}

async function operation(action) {
    if (busy) {
        text('operation-status', 'Wait for the current local operation to finish.');
        return;
    }
    busy = true;
    element('btn-scan').disabled = true;
    text('operation-status', 'Working locally…');
    try {
        await action();
        text('operation-status', 'Local operation finished. Review scope and limitations before relying on results.');
    } catch (error) {
        text('operation-status', `Operation failed: ${error.message}`);
    } finally {
        busy = false;
        element('btn-scan').disabled = false;
    }
}

function switchTab(tabId) {
    for (const id of ['matrix', 'wizard', 'verifier', 'dossier']) {
        const selected = id === tabId;
        element(`view-${id}`).classList.toggle('hidden', !selected);
        element(`tab-${id}`).classList.toggle('text-cyber-emerald', selected);
        element(`tab-${id}`).classList.toggle('border-cyber-emerald', selected);
    }
    if (tabId === 'dossier' && !busy) operation(loadDossier);
}

async function triggerScan() {
    currentScanData = null;
    renderFindingsList([]);
    text('header-scan-id', 'SCAN PENDING');
    text('scan-fingerprint-display', 'No current result');
    text('exposure-amount', 'NOT ASSESSED');
    const data = await request('/api/scan', {});
    currentScanData = data;
    text('header-scan-id', data.scan_id?.slice(0, 18) || 'No identifier');
    text('scan-fingerprint-display', data.scan_id);
    text('active-repo-label', `Target: ${data.target_path}`);
    const tiers = data.summary?.findings_by_tier || {};
    text('count-prohibited', tiers.prohibited || 0);
    text('count-highrisk', tiers.high_risk || 0);
    text('exposure-amount', 'REVIEW REQUIRED');
    text('exposure-desc', 'Findings do not establish liability; no findings does not establish compliance.');
    renderFindingsList(data.findings || []);
}

function renderFindingsList(findings) {
    const container = element('findings-list-container');
    container.replaceChildren();
    text('findings-count-badge', findings.length);
    text('count-prohibited', currentScanData?.summary?.findings_by_tier?.prohibited || 0);
    text('count-highrisk', currentScanData?.summary?.findings_by_tier?.high_risk || 0);
    if (!findings.length) {
        container.append(node('p', currentScanData
            ? 'No findings reported within the scan scope. This is not evidence of compliance.'
            : 'No current scan result.', 'p-6 text-xs text-text-secondary'));
        renderCodeSnippet(null);
        return;
    }
    for (const [index, finding] of findings.entries()) {
        const button = node('button', '', 'w-full text-left p-3 border-b border-border-slate hover:bg-slate-card-hover');
        button.append(
            node('div', `${finding.rule_id} · ${finding.severity}`, 'text-xs text-alert-amber font-mono'),
            node('div', `${finding.location?.file_path}:${finding.location?.start_line}`, 'text-xs text-text-muted font-mono'),
            node('div', finding.title, 'text-xs text-text-primary'),
        );
        button.addEventListener('click', () => selectFinding(index));
        container.append(button);
    }
    selectFinding(0);
}

function selectFinding(index) {
    selectedFindingIndex = index;
    const finding = currentScanData?.findings?.[index];
    renderCodeSnippet(finding);
}

function renderCodeSnippet(finding) {
    for (const id of ['cfg-source-code', 'cfg-prop-code', 'cfg-bifurcation-code', 'cfg-sink-code']) {
        text(id, 'No finding selected.');
    }
    text('selected-rule', finding ? `Finding: ${finding.rule_id}` : 'Finding: --');
    text('selected-remediation', finding?.remediation || 'Select a finding to review its suggested remediation.');
    text('code-viewer-filename', `File: ${finding?.location?.file_path || '--'}`);
    text('code-viewer-lines', `Line: ${finding?.location?.start_line || '--'}`);
    element('code-viewer-content').replaceChildren(node(
        'pre', finding?.code_snippet || 'No source snippet available.',
        'text-text-primary whitespace-pre-wrap font-mono text-xs',
    ));
    if (!finding) return;
    const steps = finding.flow_steps || [];
    const source = steps.find(step => step.step_type === 'source');
    const propagation = steps.find(step => step.step_type === 'propagation');
    const sink = steps.find(step => step.step_type === 'sink');
    text('cfg-source-code', source?.code_snippet || source?.message || `${finding.rule_id}: ${finding.article}`);
    text('cfg-prop-code', propagation?.code_snippet || propagation?.message || finding.title);
    text('cfg-bifurcation-code', `Heuristic finding (${finding.severity}); inspect context and actual controls.`);
    text('cfg-sink-code', sink?.code_snippet || sink?.message || finding.code_snippet || finding.message);
}

async function copyRemediation() {
    const finding = currentScanData?.findings?.[selectedFindingIndex];
    if (!finding) throw new Error('Select a finding first.');
    await navigator.clipboard.writeText(finding.remediation || 'No remediation supplied.');
}

async function evaluateStatutoryAssessment() {
    text('wizard-tier-title', 'ASSESSMENT PENDING');
    text('wizard-tier-badge', 'NOT ASSESSED');
    element('wizard-obligations-list').replaceChildren();
    const context = {
        system_name: element('wizard-sys-name').value || 'AI System',
        intended_purpose: element('wizard-purpose').value,
        role: element('wizard-role').value,
    };
    for (const select of document.querySelectorAll('[data-context]')) {
        context[select.dataset.context] = select.value === '?' ? null : select.value === 'yes';
    }
    const data = await request('/api/assess', {
        context,
    });
    text('wizard-tier-title', data.title);
    text('wizard-tier-badge', data.tier_badge);
    element('wizard-obligations-list').replaceChildren(...data.obligations.map(
        item => node('li', `${item.article}: ${item.desc}`),
    ));
}

function resetVerification() {
    element('verifier-result-panel').dataset.verification = 'unverified';
    text('verifier-status-text', 'NOT VERIFIED');
    text('verifier-status-badge', 'NOT VERIFIED');
    for (const id of ['v-signer-id', 'v-timestamp', 'v-scan-id', 'v-key-fingerprint']) text(id, '--');
}

async function handleEvidenceFile(file) {
    uploadedBundle = null;
    resetVerification();
    element('dropzone').replaceChildren(node('span', 'Select an evidence JSON file (up to 1 MiB).'));
    if (!file) return;
    if (file.size > MAX_EVIDENCE_BYTES) throw new Error('Evidence file exceeds the 1 MiB upload limit.');
    const raw = await file.text();
    const bundle = JSON.parse(raw);
    if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
        throw new Error('Evidence must be a JSON object.');
    }
    uploadedBundle = raw;
    element('dropzone').replaceChildren(
        node('span', `${file.name} (loaded, not verified)`, 'text-cyber-emerald text-xs font-mono'),
        node('span', `Unverified signer label: ${bundle.signer_identity || 'Unknown'}`, 'text-text-muted text-xs font-mono'),
    );
}

async function executeVerification() {
    resetVerification();
    if (!uploadedBundle) throw new Error('Select an evidence bundle first.');
    const data = await request('/api/verify', {
        bundle: uploadedBundle, public_key: element('verifier-public-key').value,
    });
    element('verifier-result-panel').dataset.verification = data.valid ? 'valid' : 'invalid';
    text('verifier-status-text', data.valid ? 'SIGNATURE MATCHES SUPPLIED KEY' : 'VERIFICATION FAILED');
    text('verifier-status-badge', data.valid ? 'MATCH' : 'INVALID');
    text('v-signer-id', data.signer_id);
    text('v-timestamp', data.signed_at);
    text('v-scan-id', data.scan_id);
    text('v-key-fingerprint', data.fingerprint);
}

async function loadDossier() {
    dossierMarkdown = null;
    text('dossier-preview-content', 'Generating draft for review…');
    try {
        const data = await request('/api/docgen', {
            name: element('wizard-sys-name').value || 'AI System', version: 'unspecified',
        });
        dossierMarkdown = data.markdown;
        element('dossier-preview-content').replaceChildren(node(
            'pre', data.markdown, 'text-text-primary whitespace-pre-wrap',
        ));
    } catch (error) {
        text('dossier-preview-content', 'No complete draft is available.');
        throw error;
    }
}

function download(content, filename, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function exportSARIF() {
    const response = await fetch('/api/scan?format=sarif', { signal: AbortSignal.timeout(35000) });
    if (!response.ok) throw new Error((await response.json()).error || 'SARIF export failed.');
    download(await response.text(), 'aicomply-results.sarif', 'application/json');
}

function downloadDossierMD() {
    if (!dossierMarkdown) throw new Error('Generate a complete draft first.');
    download(dossierMarkdown, 'ANNEX_IV_TECHNICAL_DOCS.md', 'text/markdown');
}

document.addEventListener('DOMContentLoaded', () => {
    const questions = [
        ['is_ai', '¿Es un sistema de IA según el Art. 3?'],
        ['eu_scope', '¿Está dentro del ámbito territorial del Art. 2?'],
        ['prohibited_practice', '¿Hay indicios de prácticas del Art. 5, tras revisar condiciones y excepciones?'],
        ['annex_i_product', '¿Es producto o componente de seguridad de un producto del Anexo I?'],
        ['third_party_conformity', '¿La normativa del producto exige evaluación por terceros?'],
        ['annex_iii_use', '¿Tiene una finalidad incluida en el Anexo III?'],
        ['profiling', '¿Realiza perfilado de personas físicas?'],
        ['narrow_exception', '¿Se ha documentado excepción del Art. 6(3), sin riesgo significativo ni influencia material?'],
        ['transparency', '¿Interactúa con personas, genera contenido sintético o usa biometría/emociones sujeto al Art. 50?'],
        ['gpai_provider', '¿La organización provee un modelo de propósito general (GPAI)?'],
        ['personal_data', '¿Se tratan datos personales?'],
        ['solely_automated_significant_decision', '¿Hay decisiones exclusivamente automatizadas con efectos jurídicos o similares significativos?'],
    ];
    for (const [key, question] of questions) {
        const group = node('div', '', 'flex flex-col gap-2');
        const label = node('label', question, 'text-xs text-text-secondary');
        label.htmlFor = `context-${key}`;
        const select = node('select', '', 'bg-obsidian border border-border-slate px-3.5 py-2 text-xs text-text-primary');
        select.id = label.htmlFor;
        select.dataset.context = key;
        for (const [value, title] of [['?', 'Desconocido / pendiente'], ['yes', 'Sí'], ['no', 'No']]) {
            const option = node('option', title);
            option.value = value;
            select.append(option);
        }
        group.append(label, select);
        element('wizard-context').append(group);
    }
    for (const button of document.querySelectorAll('[data-tab]')) {
        button.addEventListener('click', () => switchTab(button.dataset.tab));
    }
    const actions = {
        scan: triggerScan, assess: evaluateStatutoryAssessment, verify: executeVerification,
        'copy-remediation': copyRemediation, 'export-sarif': exportSARIF,
        'download-dossier': downloadDossierMD, print: () => window.print(),
    };
    for (const button of document.querySelectorAll('[data-action]')) {
        const action = button.dataset.action;
        if (action === 'select-evidence') {
            button.addEventListener('click', () => element('evidence-file-input').click());
        } else {
            button.addEventListener('click', () => operation(actions[action]));
        }
    }
    element('evidence-file-input').addEventListener('change', event => {
        const file = event.target.files[0];
        operation(() => handleEvidenceFile(file));
    });
    element('verifier-public-key').addEventListener('input', resetVerification);
    element('dropzone').addEventListener('dragover', event => event.preventDefault());
    element('dropzone').addEventListener('drop', event => {
        event.preventDefault();
        operation(() => handleEvidenceFile(event.dataTransfer.files[0]));
    });
    operation(triggerScan);
});
