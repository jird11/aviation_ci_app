/* Aero_EWS dashboard controller: run-bound rendering, review controls, and source-audit views. */
'use strict';

    let report = null;
    let catalog = [];
    let currentMode = 'executive';
    let selectedEventId = null;
    let signalScope = 'direct';
    let frozen = false;
    let lastRunning = false;
    let activeRunId = null;
    let progressStart = null;
    let currentPhase = 0;
    let rejectedIds = [];
    let auditRowsExpanded = false;
    let filterAudit = { runId: null, documents: [], collection: [], loaded: false, error: null };
    // Track each scan as a distinct UI epoch; discard late results from earlier runs.
    const SESSION_KEY = 'aero_ews_active_scan_v2';
    let scanSession = null;
    let scanEpoch = 0;
    let auditEpoch = 0;
    let auditRequestVersion = 0;
    let auditFetching = false;
    let submissionInFlight = false;
    let progressTimer = null;
    let logsRequestInFlight = false;
    let dataRequestInFlight = false;
    let lastPollError = null;
    let serverRunId = null;
    let serverRunState = null;
    try {
        const stored = JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null');
        if (stored && /^RUN-[A-Za-z0-9-]+$/.test(stored.runId || '')) {
            scanSession = { ...stored, state: stored.state || 'RUNNING' };
            activeRunId = stored.runId;
            progressStart = stored.startedAt || Date.now();
        }
    } catch { try { sessionStorage.removeItem(SESSION_KEY); } catch {} }

    const $ = (id) => document.getElementById(id);
    const esc = (v) => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

    const failedOutcomes = new Set(['ANALYSIS_FAILED', 'VALIDATION_FAILED', 'SOURCE_UNAVAILABLE']);
    const phaseLabels = [
        'Planning / KIT to KIQ',
        'OSINT collection',
        'Relevance filtering and analysis',
        'Evidence quality assurance',
        'Editorial synthesis',
        'Independent scoring and validation'
    ];

    const sourceUrl = (v) => {
        try {
            const u = new URL(String(v));
            return ['http:', 'https:'].includes(u.protocol) ? u.href : null;
        } catch {
            return null;
        }
    };

    /* Presentation rules mirror evidence gates; the backend remains authoritative. */
    const isConfirmedCritical = (t) =>
        Number(t.threat_score) >= 8 &&
        t.validation_status === 'SUPPORTED' &&
        t.confidence_level === 'HIGH' &&
        t.escalation_level === 'CRITICAL_CONFIRMED_ALERT' &&
        t.program_relevance === 'DIRECT_KIT_MATCH';

    const needsReview = (t) => t.validation_status !== 'SUPPORTED';

    // Rank signals for display without changing their validated backend status.
    // Tier 1: fully confirmed critical alerts.
    // Tier 2: supported findings with elevated potential severity.
    // Tier 3: high-severity candidates still requiring verification.
    // Tier 4: remaining supported findings.
    // Tier 5: remaining preliminary or unsupported signals.
    // Use the confirmed-critical gate and evidence status for presentation ranking;
    // the 1–10 severity score alone never confirms a critical event.
    function getPriorityTier(t) {
        if (isConfirmedCritical(t)) return 1;
        if (!needsReview(t) && Number(t.threat_score) >= 5) return 2;
        if (needsReview(t) && Number(t.threat_score) >= 7) return 3;
        if (!needsReview(t)) return 4;
        return 5;
    }

    const prioritySort = (a, b) =>
        (getPriorityTier(a) - getPriorityTier(b)) ||
        (Number(b.threat_score || 0) - Number(a.threat_score || 0));

    // Format source and run dates in UTC to avoid client-timezone reinterpretation.
    function formatHumanDate(isoStr, includeTime = false) {
        if (!isoStr || isoStr === 'DATE_UNKNOWN' || isoStr === '—') return 'Unknown';
        const d = new Date(isoStr.length === 10 ? isoStr + 'T00:00:00Z' : isoStr);
        if (isNaN(d.getTime())) return String(isoStr).slice(0, 10);
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const day = String(d.getUTCDate()).padStart(2, '0');
        const mon = months[d.getUTCMonth()];
        const yr = d.getUTCFullYear();
        if (!includeTime) return `${day} ${mon} ${yr}`;
        const hh = String(d.getUTCHours()).padStart(2, '0');
        const mm = String(d.getUTCMinutes()).padStart(2, '0');
        return `${day} ${mon} ${yr} · ${hh}:${mm} UTC`;
    }

    // Restrict compact signal previews to a short, readable summary.
    function firstSentence(text, maxLen = 135) {
        if (!text) return 'No description available.';
        const clean = String(text).replace(/\s+/g, ' ').trim();
        const match = clean.match(/^[^.!?]+[.!?]/);
        const sentence = match ? match[0].trim() : clean;
        return sentence.length > maxLen ? sentence.slice(0, maxLen - 1).trim() + '…' : sentence;
    }

    // Translate backend validation states into readable evidence labels.
    function formatEvidenceLine(t) {
        if (isConfirmedCritical(t)) return 'SUPPORTED · Confirmed critical';
        if (t.validation_status === 'SUPPORTED') {
            const conf = (t.confidence_level || 'MEDIUM').toLowerCase();
            return `SUPPORTED · ${conf.charAt(0).toUpperCase() + conf.slice(1)} confidence`;
        }
        if (t.validation_status === 'PARTIALLY_SUPPORTED') {
            return 'PARTIALLY SUPPORTED · Requires verification';
        }
        return 'UNVERIFIED · Requires verification';
    }

    // Prefer an action linked by event ID; otherwise show an advisory fallback.
    function getLinkedActionText(t) {
        const linked = (report?.action_plan || []).find(a => (a.related_event_ids || []).includes(t.event_id));
        if (linked && linked.action) return firstSentence(linked.action, 95);
        if (needsReview(t)) return 'Verify claim against primary OEM or regulatory sources.';
        return 'Assess downstream supplier and schedule exposure.';
    }

    /* View switching and auxiliary panels: presentation state only. */
    // Switch between executive and analyst views without changing report data.
    function switchView(mode) {
        currentMode = mode === 'analyst' ? 'analyst' : 'executive';
        $('executive-view').classList.toggle('hidden', Boolean(scanSession) || currentMode !== 'executive');
        $('analyst-view').classList.toggle('hidden', Boolean(scanSession) || currentMode !== 'analyst');
        $('btn-mode-exec').classList.toggle('active', currentMode === 'executive');
        $('btn-mode-analyst').classList.toggle('active', currentMode === 'analyst');
        $('btn-mode-exec').setAttribute('aria-selected', String(currentMode === 'executive'));
        $('btn-mode-analyst').setAttribute('aria-selected', String(currentMode === 'analyst'));
        if (currentMode === 'analyst') {
            renderAnalyst();
        }
    }

    // Expose secondary tools on demand to keep the primary dashboard uncluttered.
    function openDrawer(id) {
        $('more-menu').open = false;
        const dialog = $(id);
        if (!dialog) return;
        dialog.classList.add('open');
        dialog.querySelector('.drawer-header button, input, select')?.focus({ preventScroll: true });
    }

    // Return to the current dashboard view without discarding report state.
    function closeDrawer(id) {
        $(id)?.classList.remove('open');
    }

    // Open the source audit and fetch its details on demand.
    function openSourceAuditDrawer() {
        openDrawer('audit-drawer');
        loadFilterAudit();
    }

    // Keep connector health and log diagnostics outside the executive summary.
    function openSystemStatusDrawer() {
    openDrawer('status-drawer');
    renderTechnical();
}

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            ['config-drawer', 'kiq-drawer', 'audit-drawer', 'status-drawer'].forEach(closeDrawer);
            if ($('full-report-modal').classList.contains('open')) closeFullReport();
        }
    });

    /* Scan lifecycle: bind asynchronous updates to an active run ID and UI epoch. */
    function setScanSession(next) {
        scanEpoch++;
        auditEpoch++;
        auditRequestVersion++;
        auditFetching = false;
        scanSession = next;
        report = null;
        filterAudit = { runId: null, documents: [], collection: [], loaded: false, error: null };
        auditRowsExpanded = false;
        selectedEventId = null;
        rejectedIds = [];
        lastPollError = null;
        $('analyst-workspace').classList.remove('inspector-open');
        $('event-inspector').classList.add('hidden');
        ['kiq-drawer', 'audit-drawer', 'status-drawer'].forEach(closeDrawer);
        $('audit-search').value = '';
        $('audit-scope').value = 'all';
        $('coverage-audit-count').textContent = 'View audit →';
        $('menu-audit-badge').textContent = '';
        $('menu-kiq-badge').textContent = '';
        if (next) {
            try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(next)); } catch {}
            activeRunId = next.runId;
            progressStart = next.startedAt || Date.now();
            currentPhase = 1;
        } else {
            try { sessionStorage.removeItem(SESSION_KEY); } catch {}
        }
        renderAll();
        renderSourceAudit();
    }

    function setScanState(state) {
        if (!scanSession) return;
        scanSession.state = state;
        try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(scanSession)); } catch {}
        renderScanState();
        renderHeaderAndStatus();
    }

    function renderScanState() {
        const visible = Boolean(scanSession);
        $('scan-state-panel').classList.toggle('hidden', !visible);
        $('executive-view').classList.toggle('hidden', visible || currentMode !== 'executive');
        $('analyst-view').classList.toggle('hidden', visible || currentMode !== 'analyst');
        if (!visible) return;
        const state = String(scanSession.state || 'RUNNING').toUpperCase();
        const isRunning = ['RUNNING', 'QUEUED', 'STARTING', 'CANCELLING'].includes(state);
        const isFailed = ['FAILED', 'CANCELLED'].includes(state);
        const title = isRunning ? 'Scan in progress' : isFailed ? 'Scan did not complete' : 'Awaiting this run’s report';
        $('scan-state-title').textContent = title;
        $('scan-state-context').textContent = `KIT: ${scanSession.query || 'Active server-side scan'} · Run: ${scanSession.runId}`;
        $('scan-state-badge').className = `state-pill ${isFailed ? 'state-error' : isRunning ? 'state-active' : ''}`;
        $('scan-state-badge').textContent = state === 'CANCELLING' ? 'Cancelling' : state === 'COMPLETED' ? 'Report pending' : state;
        $('scan-state-message').textContent = isFailed
            ? 'No report for this run is available. The previous scan is not presented as a current result. Review the diagnostic log and start a new scan if needed.'
            : state === 'COMPLETED'
                ? 'Processing has ended. Waiting for a report with the matching run ID; previous results remain hidden.'
                : 'The previous report and its KIQs are hidden. This view will update only after results from the active run are available.';
        $('scan-timeline').innerHTML = phaseLabels.map((label, idx) => {
            const step = idx + 1;
            const completed = isRunning && step < currentPhase;
            const active = isRunning && step === currentPhase;
            return `<div class="scan-step ${completed ? 'is-done' : ''} ${active ? 'is-current' : ''}">
                <span class="scan-step-index" aria-hidden="true">${completed ? '✓' : step}</span>
                <span>${esc(label)}</span>
                <span class="scan-step-state">${completed ? 'Passed' : active ? 'Active' : 'Pending'}</span>
            </div>`;
        }).join('');
    }

    // Extract the run ID used to reject stale or unrelated report snapshots.
    function reportRunId(data) {
        return String(data?.run_id || data?.run_metadata?.run_id || '').trim();
    }

    /* Dashboard header and status rendering */
    // Show assessment status before risk conclusions; distinguish missing, failed, partial,
    // and completed outcomes independently of event severity.
    function renderHeaderAndStatus() {
        if (scanSession) {
            const state = String(scanSession.state || 'RUNNING').toUpperCase();
            const failed = state === 'FAILED' || state === 'CANCELLED';
            $('header-kit-title').textContent = scanSession.query || 'Active intelligence scan';
            $('run-stamp').textContent = `Current run: ${scanSession.runId} · ${state}`;
            $('status-line').className = `status-banner ${failed ? 'variant-failed' : 'variant-verify'}`;
            $('status-headline').textContent = failed ? 'SCAN INCOMPLETE' : state === 'COMPLETED' ? 'AWAITING CURRENT REPORT' : 'SCAN IN PROGRESS';
            $('status-detail').textContent = failed
                ? ' · This scan did not produce a verified current report'
                : ' · Previous run data and KIQs are hidden';
            $('status-actions').innerHTML = '';
            return;
        }
        const md = report?.run_metadata || {};
        const signals = report?.threats || [];
        const confirmed = signals.filter(isConfirmedCritical);
        const review = signals.filter(needsReview);
        const outcome = report?.outcome_status || 'IDLE';
        const failed = failedOutcomes.has(outcome);

        // Update the application title and active KIT context.
        $('header-kit-title').textContent = md.query || $('query')?.value || 'Aerospace Supply Chain Monitoring';
        if (md.completed_at) {
            const staleNote = md.is_stale ? ' · Stale (>24h)' : '';
            $('run-stamp').textContent = `Last analysis: ${formatHumanDate(md.completed_at, true)} · Scope: ${md.analysis_scope || '—'}${staleNote}`;
        } else {
            $('run-stamp').textContent = 'Last analysis: No completed run';
        }

        // Present the appropriate analysis and review status.
        const banner = $('status-line');
        const headline = $('status-headline');
        const detail = $('status-detail');
        const actions = $('status-actions');
        actions.innerHTML = '';

        if (!md.completed_at || outcome === 'IDLE' || report?.report_id === 'NONE') {
    banner.className = 'status-banner variant-complete';
    headline.textContent = 'NO ANALYSIS AVAILABLE';
    detail.textContent = ' – Run a scan to assess the selected topic';

} else if (failed) {
    banner.className = 'status-banner variant-failed';
            headline.textContent = 'ASSESSMENT INCOMPLETE';
            detail.textContent = ` – Risk status cannot be determined (${outcome})`;
        } else if (outcome === 'PARTIAL_SUCCESS' || md.pipeline_degraded) {
    banner.className = confirmed.length
        ? 'status-banner variant-critical'
        : 'status-banner variant-failed';

    headline.textContent = 'PARTIAL RESULTS';
    detail.textContent = ' – Some processing stages were unavailable';

    if (confirmed.length) {
        detail.textContent += ` · ${confirmed.length} confirmed critical alert(s)`;
    }

} else if (outcome === 'INSUFFICIENT_DATA') {
    banner.className = 'status-banner variant-failed';
    headline.textContent = 'INSUFFICIENT DATA';
    detail.textContent = ' – Available sources do not allow a reliable assessment';

} else if (confirmed.length > 0) {
    banner.className = 'status-banner variant-critical';
            headline.textContent = '▲ CONFIRMED CRITICAL ALERT';
            detail.textContent = ` – ${confirmed.length} ${confirmed.length === 1 ? 'event requires' : 'events require'} immediate attention`;
        } else if (review.length > 0) {
            banner.className = 'status-banner variant-verify';
            headline.textContent = '● VERIFICATION REQUIRED';
            detail.textContent = ` – ${review.length} preliminary ${review.length === 1 ? 'signal identified' : 'signals identified'} · No confirmed critical threats`;
        } else {
            banner.className = 'status-banner variant-complete';
            headline.textContent = 'MONITORING COMPLETE';
            detail.textContent = signals.length
                ? ` – No confirmed critical threats detected (${signals.length} supported ${signals.length === 1 ? 'signal' : 'signals'} monitored)`
                : ' – No confirmed critical threats detected';
        }

        if (frozen) {
            detail.textContent += ' · Live updates paused';
        }

        // Display review controls for the Analyst UI role; authorization is enforced server-side.
        const hitl = report?.hitl_status || 'IDLE';
        if (hitl.includes('APPROVED') && review.length > 0) {
    detail.textContent +=
        ' · Report approved; unverified signals still require verification';
}
        const canApprove = !failed && (hitl === 'WAITING_FOR_HITL' || hitl === 'REJECTED') && $('role-select').value === 'ANALYST';
        if (canApprove) {
            const approveBtn = document.createElement('button');
            approveBtn.type = 'button';
            approveBtn.className = 'btn tiny';
            approveBtn.textContent = 'Approve report';
            approveBtn.onclick = () => submitHITL('APPROVE');

            const rejectBtn = document.createElement('button');
            rejectBtn.type = 'button';
            rejectBtn.className = 'btn tiny';
            rejectBtn.textContent = 'Reject';
            rejectBtn.onclick = () => submitHITL('REJECT');

            actions.append(approveBtn, rejectBtn);
        }
    }

    /* Executive overview rendering */
    // Render four summary KPIs and prioritized findings alongside risk,
    // geography, and evidence coverage derived from the active snapshot.
    function renderExecutive() {
        const signals = report?.threats || [];
        const watchlist = report?.related_program_watchlist || [];
        const md = report?.run_metadata || {};
        const confirmed = signals.filter(isConfirmedCritical);
        const review = signals.filter(needsReview);
        const supported = signals.filter(t => !needsReview(t));
        const failed = failedOutcomes.has(report?.outcome_status || 'IDLE');
        const hasRun = Boolean(md.completed_at) && !failed;

        // Count retained report signals; this is not a count of verified incidents.
        $('kpi-relevant').textContent = hasRun ? String(signals.length) : '—';
        $('kpi-relevant-sub').textContent = hasRun
            ? `${supported.length} supported · ${review.length} require review`
            : 'Assessment unavailable';

        // Count only events meeting all confirmed-critical conditions.
        $('kpi-critical').textContent = hasRun ? String(confirmed.length) : '—';
        $('kpi-critical').classList.toggle('is-critical', hasRun && confirmed.length > 0);
        $('kpi-critical-sub').textContent = hasRun && confirmed.length > 0
            ? `${confirmed.length} active critical ${confirmed.length === 1 ? 'alert' : 'alerts'}`
            : 'No confirmed critical alerts';

        // Calculate the share of signals requiring verification.
        $('kpi-verify').textContent = hasRun ? String(review.length) : '—';
        const verifyPct = (hasRun && signals.length > 0) ? Math.round((review.length / signals.length) * 100) : 0;
        $('kpi-verify-sub').textContent = hasRun
            ? `${verifyPct}% of relevant signals${watchlist.length ? ` (+${watchlist.length} watchlist)` : ''}`
            : '—';

        // Show event deltas only if backend comparability and methodology checks pass.
        const comp = report?.comparison_summary || {};
        const comparable = comp.has_comparable_run === true && !comp.methodology_changed;
        if (hasRun && comparable) {
            const n = Number(comp.new_events ?? 0);
            $('kpi-new').textContent = n > 0 ? `+${n}` : String(n);
            $('kpi-new-sub').textContent = 'Compared with previous run';
        } else {
            $('kpi-new').textContent = '—';
            $('kpi-new-sub').textContent = comp.methodology_changed ? 'Methodology changed' : 'No comparable run';
        }

        // Show at most three ranked signals; unverified findings retain evidence labels.
        const sortedSignals = [...signals].sort(prioritySort);
        const top3 = sortedSignals.slice(0, 3);
        const attBox = $('attention-list');

        if (failed) {
            attBox.innerHTML = '<div class="muted small" style="padding:14px 0">Assessment incomplete. Absence of listed signals does not indicate safety.</div>';
        } else if (!top3.length) {
            attBox.innerHTML = '<div class="muted small" style="padding:14px 0">No relevant signals detected in the current monitoring scope.</div>';
        } else {
            attBox.innerHTML = top3.map(t => {
                const crit = isConfirmedCritical(t);
                const elev = !needsReview(t) && Number(t.threat_score) >= 5 && !crit;
                const prog = (t.affected_program && !t.affected_program.toLowerCase().includes('unknown'))
                    ? ` / ${t.affected_program}`
                    : '';
                const entityAndProgram = `${t.company_affected || 'Unknown entity'}${prog}`;
                const statusCls = crit ? 'is-critical' : elev ? 'is-elevated' : '';

                return `
                    <article class="attention-item ${crit ? 'is-critical' : ''}">
                        <div class="att-head">
                            <span class="att-entity">${esc(entityAndProgram)}</span>
                            <span class="att-score ${crit ? 'is-critical' : ''}">${esc(t.threat_score ?? '—')}/10</span>
                        </div>
                        <div class="att-desc">${esc(firstSentence(t.threat_description))}</div>
                        <div class="att-meta">
                            <span class="att-status-text ${statusCls}">${esc(formatEvidenceLine(t))}</span>
                            <span>·</span>
                            <span>Source: ${esc(formatHumanDate(t.publication_time))}</span>
                        </div>
                        <div class="att-footer">
                            <span class="att-action"><strong>Action:</strong> ${esc(getLinkedActionText(t))}</span>
                            <button type="button" class="link-btn" data-inspect-id="${esc(t.event_id)}">Details →</button>
                        </div>
                    </article>
                `;
            }).join('');

            attBox.querySelectorAll('[data-inspect-id]').forEach(btn => {
                btn.onclick = () => openEventInspector(btn.dataset.inspectId, true);
            });
        }

        $('view-all-signals-btn').textContent = signals.length > 0
            ? `View all ${signals.length} ${signals.length === 1 ? 'signal' : 'signals'} →`
            : 'Open Analyst View →';

        // Group report signals by risk type; selecting a bar filters the Analyst view.
        const riskCounts = {};
        signals.forEach(t => {
            const k = t.risk_type || 'OTHER';
            riskCounts[k] = (riskCounts[k] || 0) + 1;
        });
        const riskEntries = Object.entries(riskCounts).sort((a, b) => b[1] - a[1]);
        const maxRisk = riskEntries.length ? riskEntries[0][1] : 1;

        $('risk-bars').innerHTML = riskEntries.length
            ? riskEntries.map(([k, count]) => {
                const label = k.replaceAll('_', ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
                const widthPct = Math.max(8, Math.round((count / maxRisk) * 100));
                return `
                    <button type="button" class="bar-item" data-filter-risk="${esc(k)}" title="Filter Analyst View by ${esc(label)}">
                        <span>${esc(label)}</span>
                        <span class="bar-track"><span class="bar-fill" style="width:${widthPct}%"></span></span>
                        <span class="bar-val" title="${Math.round(count / signals.length * 100)}% of signals">${count} · ${Math.round(count / signals.length * 100)}%</span>
                    </button>
                `;
            }).join('')
            : '<div class="muted small">No signals to categorize</div>';

        $('risk-bars').querySelectorAll('[data-filter-risk]').forEach(btn => {
            btn.onclick = () => crossFilterAnalyst('risk', btn.dataset.filterRisk);
        });

        // Group evidenced event origins, not media reach; selecting a row filters Analyst view.
        const geoCounts = {};
        signals.forEach(t => {
            const rawGeo = (t.geographic_epicenter || 'Unknown').trim() || 'Unknown';
            geoCounts[rawGeo] = (geoCounts[rawGeo] || 0) + 1;
        });
        const geoEntries = Object.entries(geoCounts).sort((a, b) => b[1] - a[1]);

        $('geo-list').innerHTML = geoEntries.length
            ? geoEntries.map(([reg, count]) => {
                const shortReg = reg.split('(')[0].trim() || 'Unknown';
                return `
                    <button type="button" class="geo-row" data-filter-geo="${esc(reg)}" title="Filter Analyst View by origin: ${esc(reg)}">
                        <span>${esc(shortReg)}</span>
                        <strong>${count}</strong>
                    </button>
                `;
            }).join('')
            : '<div class="muted small">Unknown – 0</div>';

        $('geo-list').querySelectorAll('[data-filter-geo]').forEach(btn => {
            btn.onclick = () => crossFilterAnalyst('geo', btn.dataset.filterGeo);
        });

        // Show document-processing coverage and runtime KIQ answer status separately.
        const docsAnalyzed = Number(md.documents_analyzed ?? 0);
        const docsCollected = Number(md.documents_collected ?? 0);
        const docPct = docsCollected > 0 ? Math.min(100, Math.round((docsAnalyzed / docsCollected) * 100)) : 0;
        $('cov-docs-text').textContent = `${docsAnalyzed} / ${docsCollected} documents analyzed`;
        $('cov-docs-pct').textContent = docsCollected > 0 ? `${docPct}%` : '';
        $('cov-docs-bar').style.width = `${docPct}%`;

        const answers = (report?.kiq_answers || [])
        .filter(a => String(a.kiq_id || '').startsWith('RKIQ_'));

        const searchedAnswers = answers.filter(
            a => a.answer_status !== 'NOT_SEARCHED'
        );

        const answeredCount = searchedAnswers.filter(
            a => a.answer_status === 'ANSWERED'
        ).length;

const notSearchedCount = answers.length - searchedAnswers.length;

$('cov-kiq-btn').textContent =
    `${answeredCount} / ${searchedAnswers.length} searched KIQ answered` +
    (notSearchedCount ? ` · ${notSearchedCount} not searched` : '') +
    ' →';

$('menu-kiq-badge').textContent =
    `${answeredCount}/${searchedAnswers.length}`;

        $('cov-verify-text').textContent = `${review.length} ${review.length === 1 ? 'signal needs' : 'signals need'} verification`;
        const excluded = Math.max(0, docsCollected - docsAnalyzed);
        $('coverage-audit-count').textContent = `${excluded} not analyzed →`;
        $('coverage-audit-count').title = 'Difference between collected and analyzed records; consult source audit for documented exclusion reasons.';
    }

    // Carry a selected risk or location into the direct-signal Analyst view.
    function crossFilterAnalyst(type, value) {
    setSignalScope('direct');
    switchView('analyst');
        if (type === 'risk') $('filter-risk').value = value;
        if (type === 'geo') $('filter-geo').value = value;
        renderAnalyst();
    }

    /* Analyst workspace and event inspector rendering */
    // Populate a filter from the current report without changing its source data.
    function fillSelectOptions(id, values, labelFormatter = (x) => x) {
        const sel = $(id);
        if (!sel) return;
        const prev = sel.value;
        sel.querySelectorAll('option:not([value="all"])').forEach(o => o.remove());
        for (const v of [...new Set(values.filter(Boolean))].sort()) {
            const opt = document.createElement('option');
            opt.value = v;
            opt.textContent = labelFormatter(v);
            sel.append(opt);
        }
        sel.value = [...sel.options].some(o => o.value === prev) ? prev : 'all';
    }

    // Clear investigation filters and restore priority sorting; retain current signal scope.
    function resetFilters(rerender = true) {
        ['filter-evidence', 'filter-risk', 'filter-company', 'filter-scm', 'filter-geo'].forEach(id => {
            if ($(id)) $(id).value = 'all';
        });
        if ($('sort-by')) $('sort-by').value = 'priority';
        if (rerender) renderAnalyst();
    }

    // Separate direct KIT events from related-program watchlist entries in the UI.
    function setSignalScope(scope) {
    signalScope = scope === 'watchlist' ? 'watchlist' : 'direct';

    $('btn-scope-direct').classList.toggle('active', signalScope === 'direct');
    $('btn-scope-watchlist').classList.toggle('active', signalScope === 'watchlist');

    resetFilters(false);
    closeEventInspector();
}

// Render filterable signals; severity, evidence, and freshness remain separate fields.
function renderAnalyst() {
    const signals = signalScope === 'watchlist'
        ? (report?.related_program_watchlist || [])
        : (report?.threats || []);

    $('btn-scope-watchlist').textContent =
        `Related Watchlist (${(report?.related_program_watchlist || []).length})`;
        fillSelectOptions('filter-risk', signals.map(t => t.risk_type), x => x.replaceAll('_', ' '));
        fillSelectOptions('filter-company', signals.map(t => t.company_affected));
        fillSelectOptions('filter-scm', signals.map(t => t.scm_tier));
        fillSelectOptions('filter-geo', signals.map(t => t.geographic_epicenter || 'Unknown'));

        const fEv = $('filter-evidence').value;
        const fRisk = $('filter-risk').value;
        const fComp = $('filter-company').value;
        const fScm = $('filter-scm').value;
        const fGeo = $('filter-geo').value;

        let rows = signals.filter(t =>
            (fEv === 'all' || (fEv === 'supported' ? !needsReview(t) : needsReview(t))) &&
            (fRisk === 'all' || t.risk_type === fRisk) &&
            (fComp === 'all' || t.company_affected === fComp) &&
            (fScm === 'all' || t.scm_tier === fScm) &&
            (fGeo === 'all' || (t.geographic_epicenter || 'Unknown') === fGeo)
        );

        const sortMode = $('sort-by').value;
        rows.sort((a, b) => {
            if (sortMode === 'newest') return String(b.publication_time || '').localeCompare(String(a.publication_time || ''));
            if (sortMode === 'company') return String(a.company_affected || '').localeCompare(String(b.company_affected || ''));
            if (sortMode === 'scm') return String(a.scm_tier || '').localeCompare(String(b.scm_tier || ''));
            if (sortMode === 'geo') return String(a.geographic_epicenter || '').localeCompare(String(b.geographic_epicenter || ''));
            return prioritySort(a, b);
        });

        $('analyst-count-label').textContent = `${rows.length} of ${signals.length} signals`;

        const tbody = $('analyst-tbody');
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="muted" style="padding:20px;text-align:center">No signals match the active filters.</td></tr>`;
        } else {
            tbody.innerHTML = rows.map(t => {
                const crit = isConfirmedCritical(t);
                const elev = !needsReview(t) && Number(t.threat_score) >= 5 && !crit;
                const isSelected = selectedEventId === t.event_id;
                const prog = (t.affected_program && !t.affected_program.toLowerCase().includes('unknown'))
                    ? ` · ${t.affected_program}`
                    : '';
                const riskText = (t.risk_type || 'OTHER').replaceAll('_', ' ');
                const evLabel = t.validation_status === 'SUPPORTED'
                    ? 'SUPPORTED'
                    : t.validation_status === 'PARTIALLY_SUPPORTED'
                        ? 'PARTIAL'
                        : 'UNVERIFIED';

                return `
                    <tr tabindex="0" role="button" aria-label="Inspect ${esc(t.company_affected || 'signal')}" data-row-event="${esc(t.event_id)}" class="${crit ? 'critical-row' : ''} ${isSelected ? 'selected-row' : ''}">
                        <td>
                            <span class="row-company">${esc(t.company_affected || 'Unknown')}${esc(prog)}</span>
                            <span class="row-sub">${esc(firstSentence(t.threat_description, 110))}</span>
                        </td>
                        <td>${esc(riskText)}</td>
                        <td><strong style="${crit ? 'color:#b91c1c' : ''}">${esc(t.threat_score ?? '—')}/10</strong></td>
                        <td><span class="ev-badge ${crit ? 'is-critical' : elev ? 'is-elevated' : ''}">${esc(evLabel)}</span></td>
                        <td style="white-space:nowrap">${esc(formatHumanDate(t.publication_time))}</td>
                    </tr>
                `;
            }).join('');

            tbody.querySelectorAll('[data-row-event]').forEach(tr => {
                tr.onclick = () => openEventInspector(tr.dataset.rowEvent, false);
                tr.onkeydown = (ev) => {
                    if (ev.key === 'Enter' || ev.key === ' ') {
                        ev.preventDefault();
                        openEventInspector(tr.dataset.rowEvent, false);
                    }
                };
            });
        }

        if (selectedEventId) {
            const exists = signals.some(t => t.event_id === selectedEventId);
            if (exists) renderInspectorContent(selectedEventId);
            else closeEventInspector();
        }
    }

    // Open event-level drill-down while retaining the surrounding investigation list.
    function openEventInspector(eventId, switchToAnalyst = false) {
    const direct = (report?.threats || []).some(t => t.event_id === eventId);
    const scope = direct ? 'direct' : 'watchlist';

    if (scope !== signalScope) {
        signalScope = scope;

        $('btn-scope-direct').classList.toggle('active', direct);
        $('btn-scope-watchlist').classList.toggle('active', !direct);

        resetFilters(false);
    }

    selectedEventId = eventId;
        if (switchToAnalyst && currentMode !== 'analyst') {
            switchView('analyst');
        }
        $('analyst-workspace').classList.add('inspector-open');
        $('event-inspector').classList.remove('hidden');
        renderInspectorContent(eventId);
        renderAnalyst();
    }

    // Hide evidence detail without changing the selected report.
    function closeEventInspector() {
        selectedEventId = null;
        $('analyst-workspace').classList.remove('inspector-open');
        $('event-inspector').classList.add('hidden');
        renderAnalyst();
    }

    // Separate grounded facts from scenarios, uncertainty, and unverified assertions;
    // available review controls also depend on the selected UI role and event state.
    function renderInspectorContent(eventId) {
    const isWatchlist = signalScope === 'watchlist';

    const signals = isWatchlist
        ? (report?.related_program_watchlist || [])
        : (report?.threats || []);

    const t = signals.find(x => x.event_id === eventId);
        const box = $('inspector-content');
        if (!t || !box) return;

        const crit = isConfirmedCritical(t);
        const metricMatch = (t.validation_status === 'SUPPORTED' && t.technical_grounding_status === 'PASS')
            ? (t.fact_check_quote || '').match(/\b\d+\s+(?:aircraft\s+(?:grounded|affected)|engines\s+(?:affected|recalled)|days?\s+(?:of\s+)?delay)\b/i)
            : null;

        const sources = t.source_urls?.length ? t.source_urls : [t.evidence_citation].filter(Boolean);
        const sourceLinksHtml = sources.map(u => {
            const safe = sourceUrl(u);
            if (!safe) return '';
            let host = 'Source';
            try { host = new URL(safe).hostname; } catch {}
            return `<div><a href="${esc(safe)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8">${esc(host)} ↗</a></div>`;
        }).join('') || '<span class="muted">No traceable source link</span>';

        const linkedActions = (report?.action_plan || []).filter(a => (a.related_event_ids || []).includes(t.event_id));
        const isAnalyst = $('role-select').value === 'ANALYST' && !isWatchlist;

        box.innerHTML = `
            <!-- Event overview -->
            <div class="inspector-top">
                <div>
                    <div class="tiny muted">${esc(t.event_id)} · ${esc((t.risk_type || '').replaceAll('_', ' '))}</div>
                    <h3 class="inspector-title">${esc(t.company_affected)} – ${esc(t.affected_program || 'Program unspecified')}</h3>
                    ${isWatchlist
    ? '<div class="tiny muted">RELATED WATCHLIST · Not a direct KIT match</div>'
    : ''}
                </div>
                <button type="button" class="btn tiny" onclick="closeEventInspector()">Close ×</button>
            </div>

            <div class="inspector-sec">
                <div class="inspector-sec-title">1. Event Overview</div>
                <div class="kv-grid">
                    <div class="kv-item">
    <span>Potential Severity:</span>
    <strong style="${crit ? 'color:#b91c1c' : ''}">
        ${esc(t.threat_score)}/10
    </strong>
</div>
                    <div class="kv-item"><span>Validation:</span> <strong>${esc(t.validation_status)}</strong></div>
                    <div class="kv-item"><span>Confidence:</span> <strong>${esc(t.confidence_level)}</strong></div>
                    <div class="kv-item"><span>SCM Tier:</span> <strong>${esc(t.scm_tier)}</strong></div>
                    <div class="kv-item"><span>Component:</span> <strong>${esc(t.affected_component || 'Unspecified')}</strong></div>
                    <div class="kv-item"><span>Origin:</span> <strong>${esc(t.geographic_epicenter || 'Unknown')}</strong></div>
                    <div class="kv-item"><span>Source published:</span> <strong>${esc(formatHumanDate(t.publication_time))}</strong></div>
                    <div class="kv-item"><span>First detected:</span> <strong>${esc(formatHumanDate(t.first_seen_at))}</strong></div>
                </div>
                ${metricMatch ? `<div class="small" style="margin-top:8px"><strong>Quantitative metric:</strong> ${esc(metricMatch[0])}</div>` : ''}
            </div>

            <!-- Source evidence and grounding -->
            <div class="inspector-sec">
                <div class="inspector-sec-title">2. Evidence &amp; Grounding</div>
                <div class="small">
                    <strong>Confirmed fact:</strong>
                    ${t.validation_status === 'SUPPORTED'
                        ? esc(t.confirmed_facts || 'No explicitly confirmed facts recorded.')
                        : '<span class="muted">Not independently verified as established fact.</span>'}
                </div>
                ${t.fact_check_quote ? `<div class="quote-box">“${esc(t.fact_check_quote)}”</div>` : ''}
                <div class="small" style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:6px">
                    <span><strong>Grounding:</strong> ${esc(t.technical_grounding_status || 'UNVERIFIED')}</span>
                    <span><strong>Freshness:</strong> ${esc(t.event_freshness || 'UNKNOWN')}</span>
                </div>
                <div class="small" style="margin-top:6px"><strong>Source:</strong> ${sourceLinksHtml}</div>
                ${t.missing_data ? `<div class="small" style="margin-top:6px;color:#b45309"><strong>Missing info:</strong> ${esc(t.missing_data)}</div>` : ''}
            </div>

            <!-- Analytical assessment -->
            <div class="inspector-sec">
                <details>
                    <summary class="inspector-sec-title" style="cursor:pointer;margin:0">▸ 3. Analytical Assessment (Expand)</summary>
                    <div class="small" style="margin-top:10px;display:grid;gap:8px">
                        <div><strong>Analytical Interpretation:</strong><br>${esc(t.analytical_interpretation || 'Not available')}</div>
                        <div><strong>Hypothetical Scenario:</strong><br>${esc(t.hypothetical_scenario || 'Not available')}</div>
                        <div><strong>SCM Propagation:</strong> ${esc(t.propagation_effect || 'Direct')} ${t.impact_path?.length ? `<br><span class="tiny muted">${esc(t.impact_path.join(' → '))}</span>` : ''}</div>
                        <div><strong>Affected Programs:</strong> ${esc(t.affected_program || 'Unspecified')} ${t.hypothetical_dependencies?.length ? `<span class="tiny muted">(Shared supplier exposure: ${esc(t.hypothetical_dependencies.join(', '))})</span>` : ''}</div>
                        <div><strong>I&amp;W Assessment &amp; Score Basis:</strong><br>${esc(t.adversarial_scenario || '')}<br><span class="tiny muted">${esc(t.score_rationale || '')}</span></div>
                    </div>
                </details>
            </div>

            <!-- Recommended action -->
            <div class="inspector-sec">
                <div class="small" style="margin-bottom:8px">
    <strong>Management question:</strong>
    ${esc(t.decision_question ||
        'What should management verify or decide about this signal?')}
</div>
                ${linkedActions.length ? linkedActions.map(a => `
    <div class="small" style="margin-bottom:10px">
        <div style="font-weight:700">
            ${esc(a.action)}
        </div>

        <div class="tiny muted" style="margin-top:4px">
            Owner: ${esc(a.owner || 'Unassigned')}
            · Deadline: ${esc(a.deadline || '—')}
            · Triple-A: ${esc(a.triple_a_impact || '—')}
        </div>

        ${a.kpi ? `
            <div class="tiny" style="margin-top:4px">
                <strong>KPI:</strong> ${esc(a.kpi)}
            </div>
        ` : ''}

        ${a.pros_and_cons ? `
            <div class="tiny muted" style="margin-top:4px">
                ${esc(a.pros_and_cons)}
            </div>
        ` : ''}
    </div>
`).join('') : `
    <div class="small muted">
        ${esc(getLinkedActionText(t))}
    </div>
`}            </div>

            <!-- Analyst review -->
            <div class="inspector-sec no-print">
                <div class="inspector-sec-title">5. Analyst Decision</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px">
                    <button type="button" class="btn tiny" id="insp-confirm" ${!isAnalyst ? 'disabled' : ''}>Confirm relevance</button>
                    <button type="button" class="btn tiny" id="insp-dismiss" ${!isAnalyst ? 'disabled' : ''}>Dismiss signal</button>
                    <button type="button" class="btn tiny" id="insp-verify"
        ${isWatchlist ? 'disabled' : ''}>
    Launch targeted verification
</button>
                    <button type="button" class="btn tiny" id="insp-score" ${!isAnalyst ? 'disabled' : ''}>Review score</button>
                </div>
            </div>
        `;

        $('insp-confirm').onclick = () => feedback(t.event_id, 'CONFIRM_RELEVANT');
        $('insp-dismiss').onclick = () => {
            if (confirm('Dismiss this signal from the report?')) {
                feedback(t.event_id, 'DISMISS');
                closeEventInspector();
            }
        };
        $('insp-verify').disabled = !isAnalyst;
        $('insp-verify').onclick = (e) => targetedScan(t.event_id, e.currentTarget);
        $('insp-score').onclick = () => {
            const x = prompt('Enter adjusted Threat Score (1–10):', t.threat_score ?? 5);
            if (x !== null && Number.isInteger(Number(x)) && Number(x) >= 1 && Number(x) <= 10) {
                feedback(t.event_id, 'CORRECT_RISK_AND_SCORE', { corrected_score: Number(x) });
            }
        };
    }

    /* Secondary analysis and reporting tools */
    // Expose answered and unanswered intelligence questions with evidence coverage.
    function renderKIQDrawer() {
        const answers = report?.kiq_answers || [];
        if (scanSession) {
            $('kiq-drawer-summary').textContent = `Current KIT: ${scanSession.query || 'Active scan'} · KIQs are being generated; previous-run questions are hidden.`;
            $('kiq-grouped-content').innerHTML = '<div class="small muted">The new KIQ plan and coverage will appear when this scan publishes its own report.</div>';
            return;
        }
        const groups = [
    ['Answered',
        answers.filter(a => a.answer_status === 'ANSWERED')],

    ['Partially Answered',
        answers.filter(a => a.answer_status === 'PARTIALLY_ANSWERED')],

    ['Unanswered',
        answers.filter(a => a.answer_status === 'UNANSWERED')],

    ['Not Searched',
        answers.filter(a => a.answer_status === 'NOT_SEARCHED')]
];

        $('kiq-drawer-summary').textContent =
    `${groups[0][1].length} answered · ` +
    `${groups[1][1].length} partially answered · ` +
    `${groups[2][1].length} unanswered · ` +
    `${groups[3][1].length} not searched ` +
    `(${answers.length} total)`;

        $('kiq-grouped-content').innerHTML = answers.length ? groups.map(([title, items]) => `
            <div style="margin-bottom:16px">
                <div class="inspector-sec-title">${esc(title)} (${items.length})</div>
                ${items.length ? items.map(a => `
                    <div style="padding:10px 0;border-bottom:1px solid #f1f5f9">
                        <div class="small" style="font-weight:700;color:#0f172a">${esc(a.question)}</div>
                        <div class="small" style="color:#334155;margin-top:3px">${esc(a.answer || 'No verified answer available.')}</div>
                        <div class="tiny muted" style="margin-top:5px">
                            Evidence coverage:
                            <strong>${esc(a.evidence_coverage || 'UNKNOWN')}</strong>

                            · Temporal relevance:
                            <strong>${esc(a.temporal_relevance || 'UNKNOWN')}</strong>
                        </div>
                        <details style="margin-top:4px">
                            <summary class="tiny muted">Evidence &amp; linked events (${esc(a.kiq_id)})</summary>
                            <div class="tiny muted" style="margin-top:4px">
                                Evidence IDs: ${esc((a.evidence_ids || []).join(', ') || 'none')} ·
                                Related events: ${esc((a.related_event_ids || []).join(', ') || 'none')}
                                ${a.missing_information ? `<br>Gap: ${esc(a.missing_information)}` : ''}
                            </div>
                        </details>
                    </div>
                `).join('') : '<div class="small muted">None</div>'}
            </div>
        `).join('') : '<div class="small muted">No KIQ records generated yet.</div>';
    }

    // Identify heuristic false-negative review candidates; flags are not proven errors.
    function isAuditReviewCandidate(d) {
        const excluded = new Set(['MODEL_MISMATCH', 'EMPTY_OR_INJECTION']);
        if (excluded.has(String(d.signal_type || '').toUpperCase())) return false;
        if (['RELEVANT_EVENT', 'WEAK_SIGNAL'].includes(String(d.signal_type || '').toUpperCase())) return true;
        const q = String(report?.run_metadata?.query || '').toLowerCase();
        const title = String(d.title || '').toLowerCase();
        const modelTokens = q.match(/(?:a3\d\d(?:neo|xlr)?|a220|b7\d\d(?:x|max)?|777x|737\s?max|c919|comac|ge9x|gtf|pw1\d{3}g|leap)/g) || [];
        const risks = /\b(engine|supply|supplier|shortage|delay|defect|inspection|grounded|certification|directive|production|delivery|disruption|safety|contract|order|parts|scrap(?:ped|ping)?|tear\s?down|grounding|repair|maintenance)\b/i;
        const tokenMatch = modelTokens.length ? modelTokens.some(tok => title.includes(tok.replace(/\s+/g, '')) || title.includes(tok)) : false;
        return tokenMatch && risks.test(title);
    }

    // Fetch filtering logs only when needed; preserve run-specific provenance.
    async function loadFilterAudit(force = false) {
        const runId = scanSession ? '' : reportRunId(report);
        if (!runId || runId === 'NONE') {
            filterAudit = { runId: null, documents: [], collection: [], loaded: false, error: null };
            renderSourceAudit();
            return;
        }
        if (!force && filterAudit.runId === runId && (filterAudit.loaded || auditFetching)) {
            renderSourceAudit();
            return;
        }
        const epoch = auditEpoch;
        const requestVersion = ++auditRequestVersion;
        auditFetching = true;
        filterAudit = { runId, documents: [], collection: [], loaded: false, error: null };
        renderSourceAudit();
        try {
            const res = await fetch('/api/filter-audit?run_id=' + encodeURIComponent(runId), { cache: 'no-store' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            if (epoch !== auditEpoch || requestVersion !== auditRequestVersion || reportRunId(report) !== runId || scanSession) return;
            filterAudit = {
                runId,
                documents: Array.isArray(data.documents) ? data.documents : [],
                collection: Array.isArray(data.collection_exclusions) ? data.collection_exclusions : [],
                loaded: true,
                error: null
            };
        } catch (err) {
            if (epoch !== auditEpoch || requestVersion !== auditRequestVersion || scanSession) return;
            filterAudit = { runId, documents: [], collection: [], loaded: false, error: String(err.message || err) };
        }
        if (requestVersion === auditRequestVersion) auditFetching = false;
        auditRowsExpanded = false;
        renderSourceAudit();
    }

    // Reload persisted source-exclusion evidence after a scan.
    function refreshSourceAudit() { loadFilterAudit(true); }
    function showAllAuditRows() { auditRowsExpanded = true; renderSourceAudit(); }

    // Scope displayed audit records to their originating run; do not infer missing exclusions.
    function renderSourceAudit() {
        const box = $('audit-list');
        if (!box) return;
        if (!filterAudit.runId || !filterAudit.loaded || scanSession) {
            $('audit-overview').textContent = scanSession
                ? 'A new scan is active. Awaiting its own source audit; previous exclusions are hidden.'
                : filterAudit.error ? `Audit unavailable: ${filterAudit.error}` : auditFetching ? `Loading source audit for run ${filterAudit.runId}…` : 'Run an analysis to inspect accepted and excluded sources.';
            $('audit-count').textContent = '';
            $('menu-audit-badge').textContent = '';
            $('audit-stats').innerHTML = '';
            box.innerHTML = '';
            $('collection-audit-list').innerHTML = '';
            $('collection-audit-title').textContent = 'Collection Restrictions (0)';
            $('audit-more').classList.add('hidden');
            $('audit-note').textContent = '';
            return;
        }
        const all = filterAudit.documents;
        const collection = filterAudit.collection || [];
        const rejected = all.filter(d => Number(d.is_accepted) === 0);
        const accepted = all.filter(d => Number(d.is_accepted) === 1);
        const candidates = rejected.filter(isAuditReviewCandidate);
        const stage1 = rejected.filter(d => String(d.filter_stage || '').startsWith('STAGE_1')).length;
        const stage2 = rejected.filter(d => String(d.filter_stage || '').startsWith('STAGE_2')).length;
        $('audit-count').textContent = `(${rejected.length} excluded)`;
        $('menu-audit-badge').textContent = String(rejected.length);
        $('audit-overview').textContent = `Run ${filterAudit.runId} · ${all.length} decisions recorded · ${rejected.length} excluded (${stage1} deterministic / ${stage2} semantic) · ${collection.length} collection restrictions. Counts reflect recorded audit rows, not all documents on the web.`;
        $('audit-stats').innerHTML = [
            ['Accepted', accepted.length], ['Excluded', rejected.length],
            ['Review candidates', candidates.length], ['Collection restrictions', collection.length]
        ].map(([label, value]) => `<div class="audit-stat"><strong>${value}</strong><span>${esc(label)}</span></div>`).join('');
        const scope = $('audit-scope').value;
        const search = $('audit-search').value.trim().toLowerCase();
        let rows = all.filter(d =>
            (scope === 'accepted' ? Number(d.is_accepted) === 1 : Number(d.is_accepted) === 0) &&
            (scope !== 'candidates' || isAuditReviewCandidate(d)) &&
            (scope !== 'deterministic' || String(d.filter_stage || '').startsWith('STAGE_1')) &&
            (scope !== 'semantic' || String(d.filter_stage || '').startsWith('STAGE_2')) &&
            (!search || [d.doc_id, d.title, d.url, d.source_id, d.signal_type, d.decision_rationale].some(v => String(v || '').toLowerCase().includes(search)))
        );
        if ($('audit-sort').value === 'priority') {
            rows.sort((a, b) => Number(isAuditReviewCandidate(b)) - Number(isAuditReviewCandidate(a)) || String(a.doc_id || '').localeCompare(String(b.doc_id || '')));
        } else if ($('audit-sort').value === 'source') {
            rows.sort((a, b) => String(a.source_id || '').localeCompare(String(b.source_id || '')));
        } else {
            rows.sort((a, b) => String(a.doc_id || '').localeCompare(String(b.doc_id || '')));
        }
        const shown = rows.slice(0, auditRowsExpanded ? rows.length : 10);
        box.innerHTML = shown.length ? shown.map(d => {
            const possible = Number(d.is_accepted) === 0 && isAuditReviewCandidate(d);
            const url = sourceUrl(d.url);
            const stage = String(d.filter_stage || '').startsWith('STAGE_1') ? 'Deterministic (Stage 1)' : 'Semantic (Stage 2)';
            const status = Number(d.is_accepted) === 1 ? 'ACCEPTED' : 'EXCLUDED';
            const excerpt = d.text_excerpt || d.snippet || '';
            return `<article class="audit-entry">
                <div class="audit-entry-head">
                    <strong>${esc(d.title || 'Untitled document')}</strong>
                    <span class="audit-status ${status === 'ACCEPTED' ? 'is-accepted' : ''}">${status}</span>
                </div>
                <div class="audit-meta">${esc(d.doc_id || 'ID unknown')} · ${esc(d.source_id || 'Unknown source')} · ${esc(stage)} · ${esc(d.signal_type || 'UNSPECIFIED')}</div>
                ${status === 'EXCLUDED' ? `<p class="audit-reason"><strong>Exclusion rationale:</strong> ${esc(d.decision_rationale || 'No specific rationale recorded')}</p>` : `<p class="audit-reason"><strong>Decision:</strong> ${esc(d.decision_rationale || 'Accepted for analysis')}</p>`}
                ${possible ? '<div class="audit-review-label">Review candidate · automated heuristic, not a confirmed false negative</div>' : ''}
                ${excerpt ? `<details class="audit-excerpt"><summary>Available source excerpt</summary><p>${esc(excerpt)}</p></details>` : ''}
                ${url ? `<a class="audit-source" href="${esc(url)}" target="_blank" rel="noopener noreferrer">Open original source ↗</a>` : '<span class="muted tiny">Original URL not available in this audit record</span>'}
            </article>`;
        }).join('') : '<div class="small muted audit-empty">No documents match this audit view.</div>';
        $('audit-more').classList.toggle('hidden', auditRowsExpanded || rows.length <= 10);
        $('collection-audit-title').textContent = `Collection Restrictions (${collection.length})`;
        $('collection-audit-list').innerHTML = collection.length ? collection.map(c => {
            const url = sourceUrl(c.source_url);
            return `<article class="audit-entry">
                <strong>${esc(c.title || c.source_url || 'Restricted source')}</strong>
                <p class="audit-reason">${esc(c.exclusion_type || 'COLLECTION')} · ${esc(c.reason || 'Not specified')}</p>
                ${url ? `<a class="audit-source" target="_blank" rel="noopener noreferrer" href="${esc(url)}">Open source ↗</a>` : ''}
            </article>`;
        }).join('') : '<div class="small muted">No collection-stage restrictions recorded for this run.</div>';
        $('audit-note').textContent = `Audit run: ${filterAudit.runId}. Excluded data is retained for inspection, never presented as an analyzed threat.`;
    }

    // Export available backend audit metadata; unavailable source text is not reconstructed.
    function downloadAuditCSV() {
        if (!filterAudit.loaded || !filterAudit.runId || scanSession) return;
        const headers = ['run_id', 'stage', 'decision', 'doc_id', 'source_id', 'title', 'url', 'reason', 'signal_type'];
        const entries = [
            ...filterAudit.documents.map(d => [filterAudit.runId, d.filter_stage, Number(d.is_accepted) === 1 ? 'ACCEPTED' : 'EXCLUDED', d.doc_id, d.source_id, d.title, d.url, d.decision_rationale, d.signal_type]),
            ...filterAudit.collection.map(c => [filterAudit.runId, c.source_stage || 'COLLECTION', 'EXCLUDED', '', '', c.title, c.source_url, c.reason, c.exclusion_type])
        ];
        // Escape spreadsheet formula prefixes before writing cells to the CSV export.
        const cell = value => {
            let v = String(value ?? '');
            if (/^[\t\r\n ]*[=+@-]/.test(v)) v = "'" + v;
            return '"' + v.replace(/"/g, '""') + '"';
        };
        const csv = '\ufeff' + [headers, ...entries].map(row => row.map(cell).join(',')).join('\r\n');
        const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
        const link = document.createElement('a');
        link.href = url;
        link.download = `Aero_EWS_Source_Audit_${filterAudit.runId}.csv`;
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1500);
    }

    // Display operational diagnostics separately from decision-oriented intelligence.
    function renderTechnical() {
        const md = report?.run_metadata || {};
            const temporalMetadata =
        ` · Executed: ${md.run_date_utc || '—'}` +
        ` · Reference: ${md.analysis_reference_date || md.as_of_date || '—'}` +
        ` · Reference mode: ${md.reference_date_mode || 'UNKNOWN'}` +
        ` · Collection window: ${md.collection_window_start_utc || '—'}` +
        ` → ${md.collection_window_end_utc || '—'}`;
        $('technical-panel').textContent =
    `Outcome: ${report?.outcome_status || '—'}` +
    ` · Run: ${md.run_id || '—'}` +
    ` · Scope: ${md.analysis_scope || '—'}` +
    ` · Documents: ${md.documents_analyzed ?? 0}/${md.documents_collected ?? 0}` +
    ` · Duration: ${md.total_duration_sec ?? '—'}s` +
    ` · LLM calls: ${md.llm_calls ?? '—'}` +
    ` · Scoring: ${md.scoring_status || '—'}` +
    temporalMetadata;
        const connBox = $('connector-panel');
        connBox.innerHTML = '';
        for (const [k, c] of Object.entries(report?.connector_status || {})) {
            const div = document.createElement('div');
            div.textContent = `${k}: ${c.accepted_count ?? 0}/${c.found_count ?? 0} accepted · ${c.errors?.length ? 'ERROR' : 'OK'}`;
            connBox.append(div);
        }
    }

    // Build the printable report from the active snapshot; display fields without re-verifying them.
    function openFullReport() {
        $('more-menu').open = false;
        if (scanSession) { renderScanState(); return; }
        const body = $('full-report-body');
        const md = report?.run_metadata || {};
        const signals = report?.threats || [];
        const actions = report?.action_plan || [];
        const answers = (report?.kiq_answers || [])
    .filter(a => String(a.kiq_id || '').startsWith('RKIQ_'));

const searchedAnswers = answers.filter(
    a => a.answer_status !== 'NOT_SEARCHED'
);

const answeredCount = searchedAnswers.filter(
    a => a.answer_status === 'ANSWERED'
).length;
        const failed = failedOutcomes.has(report?.outcome_status || 'IDLE');

        $('full-report-subtitle').textContent = `KIT: ${md.query || 'Not specified'} · Scope: ${md.analysis_scope || '—'} · Completed: ${formatHumanDate(md.completed_at, true)} · Run: ${md.run_id || '—'}`;
        const paragraphs = String(report?.executive_summary || 'No executive summary available.')
            .split(/\n\s*\n/).filter(Boolean).map(p => `<p>${esc(p)}</p>`).join('');

        const eventsHtml = [...signals].sort(prioritySort).map((t, i) => `
            <div class="report-row">
                <strong>${i + 1}. ${esc(t.company_affected)} (${esc(t.affected_program)}) · ${esc(t.threat_score)}/10 · ${esc(t.validation_status)}</strong>
                <p>${esc(t.threat_description)}</p>
                <p><b>Confirmed fact:</b> ${
    t.validation_status === 'SUPPORTED'
        ? esc(t.confirmed_facts || 'Not recorded')
        : 'Not established — requires verification'
}</p>
            </div>
        `).join('') || '<p>No relevant events identified.</p>';

        const actionsHtml = actions.map((a, i) => `
            <div class="report-row">
                <strong>${i + 1}. ${esc(a.action)}</strong>
                <p>Owner: ${esc(a.owner)} · Deadline: ${esc(a.deadline)} · Decision: ${esc(a.decision || 'PENDING')}</p>
            </div>
        `).join('') || '<p>No management actions proposed.</p>';

        body.innerHTML = `
            ${failed ? '<p><strong>Assessment incomplete:</strong> Analysis failed; absence of alerts does not indicate safety.</p>' : ''}
            <h2>1. Executive Summary</h2>${paragraphs}
            <h2>2. Assessed Signals (${signals.length})</h2>${eventsHtml}
            <h2>3. Recommended Management Actions (${actions.length})</h2>${actionsHtml}
            <h2>4. Evidence Coverage &amp; QA</h2>
            <p>Analyzed ${md.documents_analyzed ?? 0} of ${md.documents_collected ?? 0} documents. Answered ${answeredCount} of ${searchedAnswers.length} searched runtime KIQ questions (${answers.length - searchedAnswers.length} not searched).</p>
            <p>${esc(report?.qa_audit_summary || '')}</p>
        `;
        $('full-report-modal').classList.add('open');
    }

    // Close the full report and return to the current dashboard mode.
    function closeFullReport() {
        $('full-report-modal').classList.remove('open');
    }

    // Print the dedicated report layout while excluding operational controls.
    function printFullReport() {
        openFullReport();
        document.body.classList.add('report-print-mode');
        window.print();
    }
    window.addEventListener('afterprint', () => document.body.classList.remove('report-print-mode'));

    /* Pipeline controls and API interactions */
    // Infer a display stage from known telemetry markers; do not estimate completion time.
    function identifyPhase(lines) {
        let n = 0;
        for (const line of lines) {
            if (/\[PHASE 1 COMPLETE|\[PHASE 2: COLLECTION|\[KIQ COLLECTION|\[OSINT GATHERER/.test(line)) n = Math.max(n, 2);
            if (/\[SEMANTIC FILTER|\[PHASE 3:|\[BATCH 1\/|\[BATCH CONSOLIDATION/.test(line)) n = Math.max(n, 3);
            if (/PHASE_3B_QA|\[PHASE 3B|QA audit/.test(line)) n = Math.max(n, 4);
            if (/PHASE_4_EDITOR|\[EDITOR\]|\[PHASE 4/.test(line)) n = Math.max(n, 5);
            if (/PHASE_5_SCORING|\[SCORING\]|\[HARNESS ENGINEERING|\[EVENT ID RECONCILIATION/.test(line)) n = Math.max(n, 6);
        }
        return n || 1;
    }

    // Express the number of recognized stages; the bar is not a time-to-finish estimate.
    function renderProgress(running, state = 'RUNNING', lines = []) {
        const box = $('run-progress');
        box.classList.toggle('hidden', !running);
        document.body.classList.toggle('is-scanning', Boolean(running));
        if (!running) return;
        currentPhase = Math.max(currentPhase, identifyPhase(lines));
        const phase = Math.max(1, Math.min(6, currentPhase));
        const completed = Math.max(0, phase - 1);
        const pct = Math.round((completed / 6) * 100);
        $('progress-number').textContent = `${phase}/6`;
        $('progress-fill').style.width = `${pct}%`;
        $('progress-track').setAttribute('aria-valuenow', String(completed));
        $('progress-phase').textContent = state === 'CANCELLING' ? 'Cancellation requested' : phaseLabels[phase - 1] || 'Processing';
        const elapsedSec = progressStart ? Math.max(0, Math.floor((Date.now() - progressStart) / 1000)) : 0;
        $('progress-caption').textContent = `Elapsed ${Math.floor(elapsedSec / 60)}m ${String(elapsedSec % 60).padStart(2, '0')}s · Stage confirmations only`;
        $('progress-cancel').disabled = state === 'CANCELLING';
        if ($('cancel-btn')) $('cancel-btn').disabled = state === 'CANCELLING';
        renderScanState();
    }

    // Pause dashboard polling while the user inspects a frozen snapshot.
    function toggleFreeze() {
        frozen = !frozen;
        $('freeze-btn').textContent = frozen ? 'Resume live updates' : 'Pause live updates';
        $('more-menu').open = false;
        renderHeaderAndStatus();
        if (!frozen) { loadLogs(); loadData(); }
    }

    // Show explicit UTC date inputs only when a custom window is selected.
    function toggleDateRange() {
    const isCustom = $('scope').value === 'custom';

    $('date-range').classList.toggle('hidden', !isCustom);

    if (!isCustom) {
        $('date-from').value = '';
        $('date-to').value = '';
    }
}

    // Apply predefined KIT and scope values; actual validation occurs in the API.
    function applyPreset() {
        const cases = {
            CASE_GTF: ['Pratt Whitney PW1100G engine inspections', '365d'],
            CASE_MAX9: ['Boeing 737 MAX 9 FAA airworthiness directive', 'all'],
            CASE_777X: ['Boeing 777X FAA certification', '365d']
        };
        const presetVal = $('preset').value;
        if (cases[presetVal]) {
            $('query').value = cases[presetVal][0];
            $('scope').value = cases[presetVal][1];
            toggleDateRange();
            return;
        }
        const item = catalog.find(x => x.kiq_id === presetVal);
        if (!item) return;
        $('query').value = `${(item.monitored_entities || []).slice(0, 2).join(' ')} ${String(item.kit_title || '').split(' ')[0]}`.trim();
        $('scope').value = item.time_scope || '7d';
        toggleDateRange();
    }

    // Fetch the strategic KIQ catalog used by the scan configuration interface.
    async function loadCatalog() {
        try {
            const r = await fetch('/api/kiq-catalog');
            if (!r.ok) return;
            const d = await r.json();
            catalog = d.catalog || [];
            for (const item of catalog) {
                const opt = document.createElement('option');
                opt.value = item.kiq_id;
                opt.textContent = `[${item.kiq_id}] ${item.question}`;
                $('preset').append(opt);
            }
        } catch {}
    }

    // Synchronize the submit button and cancellation controls.
    function setRunning(on) {
        $('run-btn').disabled = Boolean(on || submissionInFlight);
        $('run-btn').textContent = on ? 'Scan in progress…' : submissionInFlight ? 'Starting…' : 'Start Scan';
        $('cancel-btn').classList.toggle('hidden', !on);
    }

    // Start a new UI scan session only after the API returns an accepted run ID.
    async function runAnalysis() {
        if (submissionInFlight || lastRunning) return;
        const q = $('query').value.trim();
        if (!q) { $('run-feedback').textContent = 'Enter a Key Intelligence Topic.'; return; }
        const platforms = [...document.querySelectorAll('input[name="platform"]:checked')].map(x => x.value);
        const replay = $('replay-run-id').value.trim();
        if (!platforms.length) { $('run-feedback').textContent = 'Select at least one source.'; return; }
        if ($('scope').value === 'custom' && (!$('date-from').value || !$('date-to').value || $('date-from').value > $('date-to').value)) {
            $('run-feedback').textContent = 'Choose a valid custom date range.';
            return;
        }
        const payload = {
            query: q, scope: $('scope').value,
            date_from: $('scope').value === 'custom' ? $('date-from').value : null,
            date_to: $('scope').value === 'custom' ? $('date-to').value : null,
            as_of_date: $('as-of-date').value || null,
            platforms, limit: Number($('limit').value),
            auto_approve: $('auto-approve').checked,
            replay_run_id: replay || null,
            use_keyword_baseline: $('keyword-baseline').checked
        };
        submissionInFlight = true;
        setRunning(false);
        $('run-feedback').textContent = 'Submitting scan…';
        try {
            const r = await fetch('/run-ews', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload), cache: 'no-store'
            });
            const d = await r.json();
            if (!r.ok) throw Error(typeof d.detail === 'string' ? d.detail : JSON.stringify(d.detail || d));
            if (!d.run_id) throw Error('Server did not provide a run ID.');
            const already = d.status === 'already_running';
            if (d.status !== 'started' && !already) throw Error(`Unexpected response: ${d.status}`);
            const next = {
                runId: d.run_id, query: already ? '' : q,
                startedAt: Date.now(), state: already ? 'RUNNING' : 'QUEUED'
            };
            setScanSession(next);
            lastRunning = true;
            currentPhase = 1;
            renderProgress(true, next.state);
            $('run-feedback').textContent = already ? 'Another scan is already running. Tracking the active run.' : '';
            closeDrawer('config-drawer');
            await loadLogs();
        } catch (e) {
            $('run-feedback').textContent = `Unable to start scan: ${e.message}`;
        } finally {
            submissionInFlight = false;
            setRunning(lastRunning);
        }
    }

    // Request cooperative cancellation; keep the run placeholder until the backend confirms state.
    async function cancelAnalysis() {
        $('progress-cancel').disabled = true;
        $('cancel-btn').disabled = true;
        try {
            const r = await fetch('/cancel-ews', { method: 'POST' });
            if (!r.ok) throw Error(`HTTP ${r.status}`);
            const d = await r.json();
            if (d.status === 'cancelling') setScanState('CANCELLING');
        } catch (e) {
            $('run-feedback').textContent = `Cancellation request failed: ${e.message}`;
            $('progress-cancel').disabled = false;
            $('cancel-btn').disabled = false;
        }
    }

    // Poll run identity and status from the API; log lines inform stage display only.
    async function loadLogs() {
        if (frozen || logsRequestInFlight) return;
        logsRequestInFlight = true;
        const epoch = scanEpoch;
        try {
            const r = await fetch('/logs?t=' + Date.now(), { cache: 'no-store' });
            if (!r.ok) throw Error(`HTTP ${r.status}`);
            const d = await r.json();
            const lines = Array.isArray(d.logs) ? d.logs : [];
            $('live-log').textContent = lines.slice(-35).join('\n');
            if (epoch !== scanEpoch) return;
            const serverRun = String(d.current_run_id || '').trim();
            serverRunId = serverRun;
            serverRunState = String(d.state || 'IDLE').toUpperCase();
            if (d.running && serverRun && (!scanSession || scanSession.runId !== serverRun) && reportRunId(report) !== serverRun) {
                // A different server-side run is active; detach the earlier report from the display.
                setScanSession({ runId: serverRun, query: '', startedAt: Date.now(), state: 'RUNNING' });
            }
            if (scanSession && (!serverRun || scanSession.runId === serverRun)) {
                const state = d.running ? (d.state || 'RUNNING') : (d.state || 'COMPLETED');
                if (state !== scanSession.state) setScanState(state);
                const mark = lines.findIndex(line => line.includes(`API REQUEST RECEIVED [${scanSession.runId}]`));
                if (mark >= 0) scanSession.seenStartMarker = true;
                const relevant = mark >= 0 ? lines.slice(mark) : scanSession.seenStartMarker ? lines : lines.filter(line => line.includes(scanSession.runId));
                currentPhase = Math.max(currentPhase, identifyPhase(relevant));
                renderScanState();
                renderProgress(Boolean(d.running), state, relevant);
                lastRunning = Boolean(d.running);
                setRunning(lastRunning);
                if (!d.running) await loadData();
            } else if (!scanSession) {
                lastRunning = Boolean(d.running);
                setRunning(lastRunning);
                renderProgress(Boolean(d.running), d.state, lines);
            }
            lastPollError = null;
        } catch (e) {
            lastPollError = `Status unavailable: ${e.message}`;
            if (scanSession) {
                $('scan-state-message').textContent = `${lastPollError}. Retry is automatic; the previous report remains hidden.`;
            }
        } finally { logsRequestInFlight = false; }
    }

    // Send event feedback with a review key; role selection alone is not authorization.
    async function feedback(id, type, extra = {}) {
        if ($('role-select').value !== 'ANALYST') return;
            try {
                const reviewKey = prompt('Enter reviewer key:');
                if (!reviewKey) return;

                const r = await fetch('/api/analyst-feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Review-Key': reviewKey
                },
                body: JSON.stringify({
                    event_id: id,
                    report_id: report?.report_id || 'ACTIVE',
                    analyst_name: 'Senior CI Analyst',
                    feedback_type: type,
                    ...extra
                })
            });
            if (!r.ok) throw Error(await r.text());
            await loadData();
        } catch (e) {
            alert('Could not save feedback: ' + e.message);
        }
    }

    // Request additional corroborating evidence for an explicitly identified gap.
    async function targetedScan(id, btn) {
        const t = (report?.threats || []).find(x => x.event_id === id);
        if (!t) return;
        btn.disabled = true;
        btn.textContent = 'Scanning…';
        try {
            const r = await fetch('/api/targeted-kiq-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    event_id: id,
                    company_affected: t.company_affected || '',
                    what_is_missing: t.missing_data || 'Primary-source verification',
                    affected_kiq_id: (t.kiq_ids || [])[0] || '',
                    scope: report?.run_metadata?.analysis_scope || '30d'
                })
            });
            const d = await r.json();
            if (!r.ok) throw Error(JSON.stringify(d));
            btn.textContent = `Found: ${d.new_documents_found ?? 0}`;
            setTimeout(loadData, 800);
        } catch {
            btn.textContent = 'Retry verification';
            btn.disabled = false;
        }
    }

    // Submit the review decision to the backend; the UI role is not a security boundary.
    async function submitHITL(decision) {
        if ($('role-select').value !== 'ANALYST') return;
        if (failedOutcomes.has(report?.outcome_status || 'IDLE')) {
            alert('Incomplete analyses cannot be approved.');
            return;
        }
        const reviewKey = prompt('Enter reviewer key:');
        if (!reviewKey) return;
        const reason = decision === 'REJECT'
            ? (prompt('Reason for rejection:', 'Insufficient primary-source corroboration') || 'Rejected by analyst')
            : 'Reviewed source evidence and output.';
        try {
            const r = await fetch('/approve-ews', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Analyst-Role': 'ANALYST',
                    'X-Review-Key': reviewKey
                },
                body: JSON.stringify({
                    report_id: report?.report_id || 'MANUAL',
                    version: report?.version || 1,
                    decision,
                    reviewer_name: 'Senior CI Analyst',
                    reviewer_role: 'ANALYST',
                    rejected_event_ids: rejectedIds,
                    rationale: reason,
                    threats: report?.threats || [],
                    action_plan: report?.action_plan || [],
                    executive_summary: report?.executive_summary || '',
                    qa_audit_summary: report?.qa_audit_summary || '',
                    run_metadata: report?.run_metadata || {}
                })
            });
            const d = await r.json();
            if (!r.ok) throw Error(d.message || d.detail || `HTTP ${r.status}`);
            rejectedIds = [];
            await loadData();
        } catch (e) {
            alert('HITL error: ' + e.message);
        }
    }

    // Render all panes from the currently accepted report and UI session state.
    function renderAll() {
        renderScanState();
        renderHeaderAndStatus();
        if (scanSession) {
            renderKIQDrawer();
            renderTechnical();
            return;
        }
        renderExecutive();
        renderKIQDrawer();
        renderTechnical();
        if (currentMode === 'analyst') {
            renderAnalyst();
        }
    }

    // Accept fetched reports only for the active UI epoch and matching run ID.
    async function loadData() {
        if (frozen || dataRequestInFlight) return;
        dataRequestInFlight = true;
        const epoch = scanEpoch;
        try {
            const r = await fetch('/dashboard_data.json?t=' + Date.now(), { cache: 'no-store' });
            if (!r.ok) throw Error('HTTP ' + r.status);
            const next = await r.json();
            if (epoch !== scanEpoch) return;
            const incomingId = reportRunId(next);
            // Restore the latest server-side terminal run placeholder when report IDs differ.
            if (!scanSession && serverRunId && incomingId !== serverRunId &&
                ['COMPLETED', 'FAILED', 'CANCELLED'].includes(serverRunState)) {
                setScanSession({ runId: serverRunId, query: '', startedAt: Date.now(), state: serverRunState });
                return;
            }
            if (scanSession) {
                if (incomingId !== scanSession.runId) {
                    // An older approved snapshot may remain served during the active scan; do not display it.
                    renderScanState();
                    return;
                }
                // Report run ID matches the active scan; release the temporary scan placeholder.
                lastRunning = false;
                setScanSession(null);
                setRunning(false);
                renderProgress(false);
            }
            report = next;
            activeRunId = incomingId || activeRunId;
            renderAll();
            // Fetch source audit on demand for the accepted report run ID.
            if ($('audit-drawer').classList.contains('open')) loadFilterAudit();
        } catch (e) {
            if (scanSession) $('scan-state-message').textContent = `Current report unavailable (${e.message}). Retrying automatically; previous results remain hidden.`;
            console.warn('Could not fetch dashboard data', e);
        } finally { dataRequestInFlight = false; }
    }

    $('role-select').addEventListener('change', renderAll);

    loadCatalog();
    // Discover an already running scan before requesting a potentially stale report.
    (async () => {
        await loadLogs();
        await loadData();
        renderAll();
    })();
    setInterval(async () => {
        await loadLogs();
        if (scanSession || !frozen) await loadData();
    }, 4000);
    setInterval(() => {
        if (scanSession && lastRunning) renderProgress(true, scanSession.state);
    }, 1000);