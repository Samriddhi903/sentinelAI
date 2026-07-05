import { useEffect, useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Alert from '@mui/material/Alert'
import Divider from '@mui/material/Divider'
import Chip from '@mui/material/Chip'

import { sentinelApi } from '../services/sentinelApi'
import { useParams } from 'react-router-dom'

function Section({ title, children }) {
  return (
    <Box>
      <Typography sx={{ fontWeight: 900, mb: 0.8 }}>{title}</Typography>
      <Typography variant="body1" sx={{ color: 'text.secondary', whiteSpace: 'pre-wrap' }}>
        {children}
      </Typography>
      <Divider sx={{ mt: 2, opacity: 0.2 }} />
    </Box>
  )
}

function ArraySection({ title, items, emptyText = '—' }) {
  return (
    <Box>
      <Typography sx={{ fontWeight: 900, mb: 0.8 }}>{title}</Typography>
      {items?.length ? (
        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
          {items.map((item, idx) => (
            <Chip key={`${title}-${item}-${idx}`} label={item} variant="outlined" />
          ))}
        </Stack>
      ) : (
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>{emptyText}</Typography>
      )}
      <Divider sx={{ mt: 2, opacity: 0.2 }} />
    </Box>
  )
}

export default function AIReportPage() {
  const { uploadId } = useParams()

  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState(null)
  const [report, setReport] = useState(null)

  const reportText = useMemo(() => {
    if (!report) return ''
    return [
      `Executive Summary:\n${report.executive_summary || ''}`,
      `\nAttack Narrative:\n${report.attack_narrative || ''}`,
      `\nBusiness Impact:\n${report.business_impact || ''}`,
      `\nMITRE Analysis:\n${report.mitre_analysis || ''}`,
      `\nRecommended Actions:\n${(report.recommended_actions || [])
        .map((a) => `- ${a}`)
        .join('\n')}`,
    ].join('\n')
  }, [report])

  const fetchReport = async () => {
    const res = await sentinelApi.getReport(uploadId)
    setReport(res)
  }

  useEffect(() => {
    let alive = true
    const run = async () => {
      setLoading(true)
      setError(null)
      try {
        const res = await sentinelApi.getReport(uploadId)
        if (!alive) return
        setReport(res)
      } catch {
        if (!alive) return
        // report may not exist yet; allow generation
        setReport(null)
      } finally {
        if (!alive) return
        setLoading(false)
      }
    }
    run()
    return () => {
      alive = false
    }
  }, [uploadId])

  const onGenerate = async () => {
    setGenerating(true)
    setError(null)
    try {
      await sentinelApi.generateReport(uploadId)
      // refetch
      setLoading(true)
      await fetchReport()
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || 'Failed to generate report')
    } finally {
      setGenerating(false)
      setLoading(false)
    }
  }

  const exportAsPDF = async () => {
    // Popup-free PDF export.
    // The user will choose “Save as PDF” from the browser print dialog.
    try {
      const content = `AI Report (Upload: ${uploadId})\n\n${reportText}`

      const originalTitle = document.title
      const previousBody = document.body.innerHTML

      document.title = 'AI Report'

      const style = document.createElement('style')
      style.id = 'sentinel-ai-print-style'
      style.textContent =
        '@media print { * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; } }'
      document.head.appendChild(style)

      document.body.innerHTML = `<!doctype html><html><head><meta charset="utf-8"><title>AI Report</title></head><body style="font-family: Arial, sans-serif; white-space: pre-wrap; padding: 24px; background:#ffffff !important; color:#000000 !important;">${content
        .replace(/</g, '<')
        .replace(/>/g, '>')}</body></html>`

      // Let the browser render before printing.
      setTimeout(() => {
        try {
          window.print()
        } finally {
          document.body.innerHTML = previousBody
          document.title = originalTitle
          if (style?.parentNode) style.parentNode.removeChild(style)
        }
      }, 50)
    } catch (e) {
      setError(e?.message || 'Failed to export PDF')
    }
  }

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(reportText)
    } catch {
      // fallback
      const ta = document.createElement('textarea')
      ta.value = reportText
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
  }

  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 900 }}>
            AI Report
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Executive SOC report generated from your investigation. Upload: <strong>{uploadId}</strong>
          </Typography>
        </Box>

        <Stack direction="row" spacing={1}>
          <Button variant="outlined" size="small" disabled={!report} onClick={copyToClipboard}>
            Copy report
          </Button>
          <Button variant="outlined" size="small" disabled={!report} onClick={exportAsPDF}>
            Export as PDF
          </Button>
          <Button
            variant="contained"
            size="small"
            onClick={onGenerate}
            disabled={generating || loading}
          >
            {generating ? 'Generating…' : 'Generate'}
          </Button>
        </Stack>
      </Stack>

      {loading && !report ? (
        <Paper variant="outlined" sx={{ p: 3, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Paper>
      ) : error ? (
        <Alert severity="error">{error}</Alert>
      ) : null}

      {report ? (
        <Paper sx={{ p: 2.2 }}>
          <Stack spacing={1.2}>
            <Box>
              <Typography sx={{ fontWeight: 900, fontSize: 16, mb: 0.4 }}>Report Metadata</Typography>
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                Severity: <strong>{report.severity}</strong> · Risk Score: <strong>{report.risk_score}</strong> · Confidence: <strong>{report.metadata?.confidence ?? 'n/a'}</strong>
              </Typography>
            </Box>
            <Divider sx={{ opacity: 0.2 }} />

            <Section title="Executive Summary">{report.executive_summary}</Section>
            <Section title="Executive Narrative">{report.executive_narrative || report.attack_narrative}</Section>

            <Box>
              <Typography sx={{ fontWeight: 900, mb: 0.8 }}>Attack Chain</Typography>
              {Array.isArray(report.attack_chain) && report.attack_chain.length > 0 ? (
                <Stack spacing={1.2}>
                  {report.attack_chain.map((phase, idx) => (
                    <Paper key={`${phase.name}-${idx}`} variant="outlined" sx={{ p: 1.2, bgcolor: 'rgba(30,41,59,0.25)' }}>
                      <Typography sx={{ fontWeight: 850 }}>{phase.name}</Typography>
                      <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.4 }}>
                        Detections: {(phase.detections || []).join(', ')}
                      </Typography>
                      {phase.mitre?.length ? (
                        <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.4 }}>
                          MITRE: {phase.mitre.join(', ')}
                        </Typography>
                      ) : null}
                      {phase.evidence && Object.keys(phase.evidence).length ? (
                        <Box sx={{ mt: 0.6, display: 'flex', flexWrap: 'wrap', gap: 0.6 }}>
                          {Object.entries(phase.evidence).map(([key, values]) => (
                            values?.length ? (
                              <Chip key={`${phase.name}-${key}`} label={`${key}: ${values.join(', ')}`} variant="outlined" size="small" />
                            ) : null
                          ))}
                        </Box>
                      ) : null}
                    </Paper>
                  ))}
                </Stack>
              ) : (
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>No attack chain data available.</Typography>
              )}
              <Divider sx={{ mt: 2, opacity: 0.2 }} />
            </Box>

            <ArraySection title="Affected Hosts" items={report.metadata?.affected_hosts || []} />
            <ArraySection title="Affected Accounts" items={report.metadata?.affected_accounts || []} />
            <ArraySection title="External IPs" items={report.iocs?.external_ips || []} />
            <ArraySection title="Internal IPs" items={report.iocs?.internal_ips || []} />
            <ArraySection title="Hosts" items={report.iocs?.hosts || []} />
            <ArraySection title="Accounts" items={report.iocs?.accounts || []} />
            <ArraySection title="Processes" items={report.iocs?.processes || []} />
            <ArraySection title="Commands" items={report.iocs?.commands || []} />
            <ArraySection title="Files" items={report.iocs?.files || []} />
            <ArraySection title="Registry Keys" items={report.iocs?.registry_keys || []} />
            <ArraySection title="Cron Jobs" items={report.iocs?.cron_jobs || []} />
            <ArraySection title="Domains" items={report.iocs?.domains || []} />
            <ArraySection title="URLs" items={report.iocs?.urls || []} />
            <ArraySection title="Hashes" items={report.iocs?.hashes || []} />

            <Box>
              <Typography sx={{ fontWeight: 900, mb: 0.8 }}>MITRE ATT&CK</Typography>
              {(report.mitre_table || []).length ? (
                <Stack spacing={1}>
                  {report.mitre_table.map((row, idx) => (
                    <Paper key={`${row.mitre_id}-${idx}`} variant="outlined" sx={{ p: 1.1 }}>
                      <Typography sx={{ fontWeight: 850 }}>{row.technique}</Typography>
                      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                        {row.mitre_id} · {row.evidence}
                      </Typography>
                    </Paper>
                  ))}
                </Stack>
              ) : (
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>No MITRE mappings available.</Typography>
              )}
              <Divider sx={{ mt: 2, opacity: 0.2 }} />
            </Box>

            <Section title="Business Impact">{report.business_impact}</Section>
            <Section title="MITRE Analysis">{report.mitre_analysis}</Section>

            <Box>
              <Typography sx={{ fontWeight: 900, mb: 0.8 }}>Structured Recommendations</Typography>
              <Stack spacing={1.2}>
                {Object.entries(report.recommendations || {}).map(([group, items]) => (
                  <Box key={group}>
                    <Typography sx={{ fontWeight: 800, textTransform: 'capitalize' }}>{group.replace(/_/g, ' ')}</Typography>
                    {items?.length ? (
                      <Stack component="ul" sx={{ m: 0, pl: 2, '& li': { mb: 0.4 } }}>
                        {items.map((item, idx) => (
                          <li key={`${group}-${item}-${idx}`}>{item}</li>
                        ))}
                      </Stack>
                    ) : (
                      <Typography variant="body2" sx={{ color: 'text.secondary' }}>—</Typography>
                    )}
                  </Box>
                ))}
              </Stack>
              <Divider sx={{ mt: 2, opacity: 0.2 }} />
            </Box>

            <Box>
              <Typography sx={{ fontWeight: 900, mb: 0.8 }}>Recommended Actions</Typography>
              <Box sx={{ color: 'text.secondary', whiteSpace: 'pre-wrap' }}>
                {(report.recommended_actions || []).length ? (
                  <Stack component="ul" sx={{ m: 0, pl: 2, '& li': { mb: 0.5 } }}>
                    {report.recommended_actions.map((a, idx) => (
                      <li key={`${a}-${idx}`}>{a}</li>
                    ))}
                  </Stack>
                ) : (
                  <Typography variant="body2">—</Typography>
                )}
              </Box>
              <Divider sx={{ mt: 2, opacity: 0.2 }} />
            </Box>
          </Stack>
        </Paper>
      ) : !loading ? (
        <Paper variant="outlined" sx={{ p: 2.2 }}>
          <Typography sx={{ fontWeight: 850 }}>No report found yet.</Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.6 }}>
            Click <strong>Generate</strong> to create an executive SOC report for this investigation.
          </Typography>
        </Paper>
      ) : null}
    </Box>
  )
}

