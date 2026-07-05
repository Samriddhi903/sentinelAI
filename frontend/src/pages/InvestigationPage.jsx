import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Chip from '@mui/material/Chip'
import Divider from '@mui/material/Divider'
import CircularProgress from '@mui/material/CircularProgress'
import Button from '@mui/material/Button'

import { sentinelApi } from '../services/sentinelApi'
import { useNavigate, useParams } from 'react-router-dom'

export default function InvestigationPage() {
  const { uploadId } = useParams()
  const navigate = useNavigate()

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [analysis, setAnalysis] = useState(null)

  useEffect(() => {
    let alive = true
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const res = await sentinelApi.getAnalysis(uploadId)
        if (!alive) return
        setAnalysis(res)
      } catch (e) {
        if (!alive) return
        setError(e?.response?.data?.detail || e.message || 'Failed to fetch investigation')
      } finally {
        if (!alive) return
        setLoading(false)
      }
    }
    load()
    return () => {
      alive = false
    }
  }, [uploadId])

  const inv = analysis?.investigation

  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 900 }}>Investigation View</Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Incident summary and attack chain for upload <strong>{uploadId}</strong>
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button variant="outlined" size="small" onClick={() => navigate(`/timeline/${uploadId}`)}>Timeline</Button>
          <Button variant="contained" size="small" onClick={() => navigate(`/ai-report/${uploadId}`)}>AI Report</Button>
        </Stack>
      </Stack>

      {loading ? (
        <Paper variant="outlined" sx={{ p: 3, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Paper>
      ) : error ? (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography color="error" sx={{ fontWeight: 800 }}>{error}</Typography>
        </Paper>
      ) : null}

      {!loading && inv ? (
        <Stack spacing={2.2}>
          <Paper sx={{ p: 2.2 }}>
            <Stack spacing={1.2}>
              <Typography sx={{ fontWeight: 900, fontSize: 16 }}>Incident Overview</Typography>
              <Divider sx={{ opacity: 0.3 }} />

              <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5}>
                <Chip label={`Incident Type: ${inv.incident_type || '—'}`} variant="outlined" sx={{ flex: 1 }} />
                <Chip label={`Severity: ${inv.severity || '—'}`} variant="outlined" sx={{ flex: 1 }} />
              </Stack>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5}>
                <Chip label={`Risk Score: ${inv.risk_score ?? '—'}`} variant="outlined" sx={{ flex: 1 }} />
                <Chip label={`Source IP: ${inv.source_ip || '—'}`} variant="outlined" sx={{ flex: 1 }} />
              </Stack>

              <Box sx={{ mt: 1 }}>
                <Typography variant="body2" sx={{ color: 'text.secondary', mb: 0.6 }}>
                  Attack Chain
                </Typography>
                <Typography sx={{ fontWeight: 750 }}>
                  {(inv.attack_chain || []).length ? inv.attack_chain.join(' → ') : '—'}
                </Typography>
              </Box>

              <Box sx={{ mt: 1 }}>
                <Typography variant="body2" sx={{ color: 'text.secondary', mb: 0.6 }}>
                  MITRE Techniques
                </Typography>
                <Stack direction="row" sx={{ flexWrap: 'wrap' }} gap={1}>

                  {(inv.mitre_techniques || []).length ? (
                    inv.mitre_techniques.map((t) => (
                      <Chip key={t} label={t} variant="outlined" />
                    ))
                  ) : (
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>—</Typography>
                  )}
                </Stack>
              </Box>
            </Stack>
          </Paper>

          <Paper sx={{ p: 2.2 }}>
            <Typography sx={{ fontWeight: 900, fontSize: 16, mb: 1.2 }}>Detections</Typography>
            {Array.isArray(inv.detections) && inv.detections.length ? (
              <Stack spacing={1}>
                {inv.detections.map((d, idx) => (
                  <Paper
                    key={d?.detection_id || idx}
                    variant="outlined"
                    sx={{ p: 1.3, bgcolor: 'rgba(30,41,59,0.25)', borderColor: 'rgba(148,163,184,0.18)' }}
                  >
                    <Typography sx={{ fontWeight: 800 }}>
                      {d?.detection_type || d?.type || 'Detection'}
                    </Typography>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                      Severity: {String(d?.severity || '—')} · Confidence: {typeof d?.confidence === 'number' ? `${Math.round(d.confidence * 100)}%` : '—'}
                    </Typography>
                  </Paper>
                ))}
              </Stack>
            ) : (
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>No detections included in the investigation response.</Typography>
            )}
          </Paper>
        </Stack>
      ) : null}
    </Box>
  )
}

