import { useEffect, useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import CircularProgress from '@mui/material/CircularProgress'
import Chip from '@mui/material/Chip'

import { sentinelApi } from '../services/sentinelApi'
import { useParams } from 'react-router-dom'

export default function TimelinePage() {
  const { uploadId } = useParams()

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [report, setReport] = useState(null)

  useEffect(() => {
    let alive = true
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const [analysisRes, reportRes] = await Promise.all([
          sentinelApi.getAnalysis(uploadId),
          sentinelApi.getReport(uploadId).catch(() => null),
        ])
        if (!alive) return
        setAnalysis(analysisRes)
        setReport(reportRes)
      } catch (e) {
        if (!alive) return
        setError(e?.response?.data?.detail || e.message || 'Failed to load timeline')
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

  const chain = useMemo(() => {
    if (Array.isArray(report?.attack_chain) && report.attack_chain.length > 0) {
      return report.attack_chain
    }
    if (Array.isArray(analysis?.timeline?.attack_chain) && analysis.timeline.attack_chain.length > 0) {
      return analysis.timeline.attack_chain.map((phase) => ({
        name: phase.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
        detections: [],
        mitre: [],
        evidence: {},
      }))
    }
    return []
  }, [analysis, report])

  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 900, mb: 2 }}>Attack Chain</Typography>

      {loading ? (
        <Paper variant="outlined" sx={{ p: 3, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Paper>
      ) : error ? (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography color="error" sx={{ fontWeight: 800 }}>{error}</Typography>
        </Paper>
      ) : null}

      {!loading && analysis ? (
        <Paper sx={{ p: 2.2 }}>
          <Stack spacing={1.5}>
            <Typography sx={{ fontWeight: 850 }}>Observed phases</Typography>
            {chain.length ? (
              <Stack spacing={1.2}>
                {chain.map((phase, idx) => (
                  <Paper
                    key={`${phase.name}-${idx}`}
                    variant="outlined"
                    sx={{ p: 1.2, bgcolor: 'rgba(30,41,59,0.25)' }}
                  >
                    <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} alignItems={{ md: 'center' }} justifyContent="space-between">
                      <Box>
                        <Typography sx={{ fontWeight: 850 }}>{phase.name}</Typography>
                        <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.3 }}>
                          Detections: {(phase.detections || []).join(', ')}
                        </Typography>
                        {phase.mitre?.length ? (
                          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.3 }}>
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
                      </Box>
                      {idx !== chain.length - 1 ? (
                        <Typography sx={{ fontWeight: 900, display: { xs: 'none', md: 'block' } }}>→</Typography>
                      ) : null}
                    </Stack>
                  </Paper>
                ))}
              </Stack>
            ) : (
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>No attack chain data returned.</Typography>
            )}

            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              The attack chain is dynamically generated from normalized detections and MITRE mappings.
            </Typography>
          </Stack>
        </Paper>
      ) : null}
    </Box>
  )
}

